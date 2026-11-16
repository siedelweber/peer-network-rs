//! Public provisioning setup on the unchanged protected host wire path.
//! (´[ROOT-rule:observe:credential-store-contract]´)

use super::{OwnedInstance, StandingProfile};
use crate::{Configuration, scram, wire};
use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Transport,
    Protocol,
    Server,
    Inventory,
    Framing,
    MissingRole,
}

#[derive(Debug, PartialEq, Eq)]
enum PublicFrame {
    Parsed,
    Description,
    Boolean(bool),
    Completion,
    Ready,
}

// Fixture-only secret boundary: This host transport witness parses only its public inventory responses.
// Caveat: The protected provisioning response is borrowed only to validate public inventory booleans and protocol completion; the borrow ends at that parse, unexpected fields remain protected, and the framing predicates require a byte slice.
// (´[ROOT-cav:observe:secret-host-credential-inventory-readback]´)
// Justified: Only the admitted public inventory result and completion classes leave the protected response parser.
#[allow(clippy::disallowed_methods)]
fn public_frame(frame: &wire::Frame) -> Result<PublicFrame, Refusal> {
    let bytes = frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-inventory-readback]´) */);
    match frame.kind {
        b'1' if bytes.is_empty() => Ok(PublicFrame::Parsed),
        b'Z' if bytes == b"I" => Ok(PublicFrame::Ready),
        b'C' if !bytes.is_empty() && bytes.last() == Some(&0) && !bytes[..bytes.len() - 1].contains(&0) => {
            Ok(PublicFrame::Completion)
        }
        // SELECT's sole public boolean column has a fixed text-format description.
        b'T' if bytes == b"\0\x01ok\0\0\0\0\0\0\0\0\0\0\x10\0\x01\xff\xff\xff\xff\0\0" => Ok(PublicFrame::Description),
        b'D' if bytes == b"\0\x01\0\0\0\x01t" => Ok(PublicFrame::Boolean(true)),
        b'D' if bytes == b"\0\x01\0\0\0\x01f" => Ok(PublicFrame::Boolean(false)),
        _ => Err(Refusal::Protocol),
    }
}

struct RawSession {
    socket: wire::Socket,
}

impl RawSession {
    async fn open(instance: &OwnedInstance) -> Result<Self, Refusal> {
        let input = serde_json::to_vec(&serde_json::json!({
            "transport":"unix", "endpoint":instance.root.join(".s.PGSQL.5432"),
            "port":"5432", "user":"credential_public", "database":"postgres",
            "password":"credential_public_setup_password"
        }))
        .unwrap();
        let config = Configuration::acquire(Some("host-secured"), &mut input.as_slice()).map_err(|_| Refusal::Transport)?;
        let socket = tokio::time::timeout(Duration::from_secs(600), async {
            let mut socket = wire::Socket::open(&config).await.map_err(|_| Refusal::Transport)?;
            scram::login(&mut socket, &config).await.map_err(|_| Refusal::Transport)?;
            let mut key = false;
            loop {
                let frame = wire::read(&mut socket).await.map_err(|_| Refusal::Transport)?;
                match frame.kind {
                    // Neither startup parameter bytes nor the real cancellation key
                    // leave protected storage. Inventory reads establish public state.
                    b'S' => {}
                    b'K' if !key && frame.payload.len() == 8 => key = true,
                    b'Z' if key && public_frame(&frame)? == PublicFrame::Ready => break,
                    _ => return Err(Refusal::Protocol),
                }
            }
            Ok(socket)
        })
        .await
        .expect("HANG awaiting credential raw authenticated startup; last state=protected handshake")?;
        for (_, limits) in instance.process_limits() {
            super::core_limits(&limits).expect("raw issuing backend inherits one/one core limits");
        }
        Ok(Self { socket })
    }

    async fn query(&mut self, sql: &str, boolean: bool) -> Result<bool, Refusal> {
        // Every caller supplies only fixed or publicly assembled setup SQL.
        cli_common::emit(&serde_json::json!({"credential_public_statement":sql})).unwrap();
        let mut message = sql.as_bytes().to_vec();
        message.push(0);
        tokio::time::timeout(Duration::from_secs(600), async {
            wire::send(&mut self.socket, b'Q', &message)
                .await
                .map_err(|_| Refusal::Transport)?;
            let mut description = false;
            let mut value = None;
            let mut completion = false;
            let mut error = false;
            loop {
                let frame = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
                if frame.kind == b'E' {
                    error = true;
                    continue;
                }
                // ParameterStatus and diagnostics are not ordinary result data.
                if frame.kind == b'S' || frame.kind == b'N' {
                    return Err(Refusal::Protocol);
                }
                match public_frame(&frame)? {
                    PublicFrame::Description if boolean && !description && value.is_none() && !completion => description = true,
                    PublicFrame::Boolean(actual) if description && value.is_none() && !completion => value = Some(actual),
                    PublicFrame::Completion if !completion => completion = true,
                    PublicFrame::Ready => {
                        if error {
                            return Err(Refusal::Server);
                        }
                        if !completion || (boolean && value.is_none()) || (!boolean && description) {
                            return Err(Refusal::Protocol);
                        }
                        return Ok(value.unwrap_or(true));
                    }
                    _ => return Err(Refusal::Protocol),
                }
            }
        })
        .await
        .expect("HANG awaiting credential raw statement completion; last state=protected response")
    }

    async fn require(&mut self, predicate: &str) -> Result<(), Refusal> {
        if !self.query(&format!("SELECT ({predicate}) IS TRUE AS ok"), true).await? {
            return Err(Refusal::Inventory);
        }
        Ok(())
    }

    async fn outer(&mut self) -> Result<(), Refusal> {
        let mut parse = vec![0];
        parse.extend_from_slice(OUTER.as_bytes());
        parse.extend_from_slice(&[0, 0, 1, 0, 0, 0, 25]);
        tokio::time::timeout(Duration::from_secs(600), async {
            wire::send(&mut self.socket, b'P', &parse)
                .await
                .map_err(|_| Refusal::Transport)?;
            wire::send(&mut self.socket, b'S', &[])
                .await
                .map_err(|_| Refusal::Transport)?;
            let parsed = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
            if public_frame(&parsed)? != PublicFrame::Parsed {
                return Err(Refusal::Protocol);
            }
            let ready = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
            if public_frame(&ready)? != PublicFrame::Ready {
                return Err(Refusal::Protocol);
            }
            Ok(())
        })
        .await
        .expect("HANG awaiting credential raw public Parse; last state=unnamed statement")
    }

    async fn close(mut self) -> Result<(), Refusal> {
        tokio::time::timeout(Duration::from_secs(600), wire::send(&mut self.socket, b'X', &[]))
            .await
            .expect("HANG awaiting credential raw termination; last state=public terminate")
            .map_err(|_| Refusal::Transport)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inventory {
    Statements,
    Durations,
    Samples,
    Errors,
    Parameters,
    Trees,
    Statistics,
    OtherLogs,
    Jit,
    Activity,
    CrashReport,
    Modules,
    Explain,
    StatementExtension,
    UnknownFacilities,
    Helper,
    Listings,
    Counters,
    Destinations,
    ConnectionLogs,
    Background,
    Client,
    Plan,
    Core,
    Wal,
    Archive,
    Senders,
    Slots,
    Replicas,
    Titles,
    ClientCustody,
}

const INVENTORY: [Inventory; 31] = [
    Inventory::Statements,
    Inventory::Durations,
    Inventory::Samples,
    Inventory::Errors,
    Inventory::Parameters,
    Inventory::Trees,
    Inventory::Statistics,
    Inventory::OtherLogs,
    Inventory::Jit,
    Inventory::Activity,
    Inventory::CrashReport,
    Inventory::Modules,
    Inventory::Explain,
    Inventory::StatementExtension,
    Inventory::UnknownFacilities,
    Inventory::Helper,
    Inventory::Listings,
    Inventory::Counters,
    Inventory::Destinations,
    Inventory::ConnectionLogs,
    Inventory::Background,
    Inventory::Client,
    Inventory::Plan,
    Inventory::Core,
    Inventory::Wal,
    Inventory::Archive,
    Inventory::Senders,
    Inventory::Slots,
    Inventory::Replicas,
    Inventory::Titles,
    Inventory::ClientCustody,
];

const SUPPRESSIONS: &[(&str, &str)] = &[
    ("log_statement", "none"),
    ("log_min_duration_statement", "-1"),
    ("log_duration", "off"),
    ("log_min_duration_sample", "-1"),
    ("log_statement_sample_rate", "0"),
    ("log_transaction_sample_rate", "0"),
    ("log_min_error_statement", "panic"),
    ("log_min_messages", "panic"),
    ("log_error_verbosity", "terse"),
    ("log_parameter_max_length", "0"),
    ("log_parameter_max_length_on_error", "0"),
    ("debug_print_raw_parse", "off"),
    ("debug_print_parse", "off"),
    ("debug_print_rewritten", "off"),
    ("debug_print_plan", "off"),
    ("log_statement_stats", "off"),
    ("log_parser_stats", "off"),
    ("log_planner_stats", "off"),
    ("log_executor_stats", "off"),
    ("log_lock_waits", "off"),
    ("log_lock_failures", "off"),
    ("log_replication_commands", "off"),
    ("log_temp_files", "-1"),
    ("backtrace_functions", ""),
    ("track_activities", "off"),
    ("client_min_messages", "error"),
    ("plan_cache_mode", "force_generic_plan"),
];

const SETTING_NAMES: &str = "DateStyle,IntervalStyle,TimeZone,allow_alter_system,allow_in_place_tablespaces,allow_system_table_mods,application_name,archive_cleanup_command,archive_command,archive_library,archive_mode,archive_timeout,array_nulls,authentication_timeout,autovacuum,autovacuum_analyze_scale_factor,autovacuum_analyze_score_weight,autovacuum_analyze_threshold,autovacuum_freeze_max_age,autovacuum_freeze_score_weight,autovacuum_max_parallel_workers,autovacuum_max_workers,autovacuum_multixact_freeze_max_age,autovacuum_multixact_freeze_score_weight,autovacuum_naptime,autovacuum_vacuum_cost_delay,autovacuum_vacuum_cost_limit,autovacuum_vacuum_insert_scale_factor,autovacuum_vacuum_insert_score_weight,autovacuum_vacuum_insert_threshold,autovacuum_vacuum_max_threshold,autovacuum_vacuum_scale_factor,autovacuum_vacuum_score_weight,autovacuum_vacuum_threshold,autovacuum_work_mem,autovacuum_worker_slots,backend_flush_after,backslash_quote,backtrace_functions,bgwriter_delay,bgwriter_flush_after,bgwriter_lru_maxpages,bgwriter_lru_multiplier,block_size,bonjour,bonjour_name,bytea_output,check_function_bodies,checkpoint_completion_target,checkpoint_flush_after,checkpoint_timeout,checkpoint_warning,client_connection_check_interval,client_encoding,client_min_messages,cluster_name,commit_delay,commit_siblings,commit_timestamp_buffers,compute_query_id,config_file,constraint_exclusion,cpu_index_tuple_cost,cpu_operator_cost,cpu_tuple_cost,createrole_self_grant,cursor_tuple_fraction,data_checksums,data_directory,data_directory_mode,data_sync_retry,deadlock_timeout,debug_assertions,debug_discard_caches,debug_exec_backend,debug_io_direct,debug_logical_replication_streaming,debug_parallel_query,debug_pretty_print,debug_print_parse,debug_print_plan,debug_print_raw_parse,debug_print_rewritten,default_statistics_target,default_table_access_method,default_tablespace,default_text_search_config,default_toast_compression,default_transaction_deferrable,default_transaction_isolation,default_transaction_read_only,dynamic_library_path,dynamic_shared_memory_type,effective_cache_size,effective_io_concurrency,effective_wal_level,enable_async_append,enable_bitmapscan,enable_distinct_reordering,enable_eager_aggregate,enable_gathermerge,enable_group_by_reordering,enable_hashagg,enable_hashjoin,enable_incremental_sort,enable_indexonlyscan,enable_indexscan,enable_material,enable_memoize,enable_mergejoin,enable_nestloop,enable_parallel_append,enable_parallel_hash,enable_partition_pruning,enable_partitionwise_aggregate,enable_partitionwise_join,enable_presorted_aggregate,enable_self_join_elimination,enable_seqscan,enable_sort,enable_tidscan,event_source,event_triggers,exit_on_error,extension_control_path,external_pid_file,extra_float_digits,file_copy_method,file_extend_method,from_collapse_limit,fsync,full_page_writes,geqo,geqo_effort,geqo_generations,geqo_pool_size,geqo_seed,geqo_selection_bias,geqo_threshold,gin_fuzzy_search_limit,gin_pending_list_limit,gss_accept_delegation,hash_mem_multiplier,hba_file,hosts_file,hot_standby,hot_standby_feedback,huge_page_size,huge_pages,huge_pages_status,icu_validation_level,ident_file,idle_in_transaction_session_timeout,idle_replication_slot_timeout,idle_session_timeout,ignore_checksum_failure,ignore_invalid_pages,ignore_system_indexes,in_hot_standby,integer_datetimes,io_combine_limit,io_max_combine_limit,io_max_concurrency,io_max_workers,io_method,io_min_workers,io_worker_idle_timeout,io_worker_launch_interval,jit,jit_above_cost,jit_debugging_support,jit_dump_bitcode,jit_expressions,jit_inline_above_cost,jit_optimize_above_cost,jit_profiling_support,jit_provider,jit_tuple_deforming,join_collapse_limit,krb_caseins_users,krb_server_keyfile,lc_messages,lc_monetary,lc_numeric,lc_time,listen_addresses,lo_compat_privileges,local_preload_libraries,lock_timeout,log_autoanalyze_min_duration,log_autovacuum_min_duration,log_checkpoints,log_connections,log_destination,log_directory,log_disconnections,log_duration,log_error_verbosity,log_executor_stats,log_file_mode,log_filename,log_hostname,log_line_prefix,log_lock_failures,log_lock_waits,log_min_duration_sample,log_min_duration_statement,log_min_error_statement,log_min_messages,log_parameter_max_length,log_parameter_max_length_on_error,log_parser_stats,log_planner_stats,log_recovery_conflict_waits,log_replication_commands,log_rotation_age,log_rotation_size,log_startup_progress_interval,log_statement,log_statement_sample_rate,log_statement_stats,log_temp_files,log_timezone,log_transaction_sample_rate,log_truncate_on_rotation,logging_collector,logical_decoding_work_mem,maintenance_io_concurrency,maintenance_work_mem,max_active_replication_origins,max_connections,max_files_per_process,max_function_args,max_identifier_length,max_index_keys,max_locks_per_transaction,max_logical_replication_workers,max_notify_queue_pages,max_parallel_apply_workers_per_subscription,max_parallel_maintenance_workers,max_parallel_workers,max_parallel_workers_per_gather,max_pred_locks_per_page,max_pred_locks_per_relation,max_pred_locks_per_transaction,max_prepared_transactions,max_repack_replication_slots,max_replication_slots,max_slot_wal_keep_size,max_stack_depth,max_standby_archive_delay,max_standby_streaming_delay,max_sync_workers_per_subscription,max_wal_senders,max_wal_size,max_worker_processes,md5_password_warnings,min_dynamic_shared_memory,min_eager_agg_group_size,min_parallel_index_scan_size,min_parallel_table_scan_size,min_wal_size,multixact_member_buffers,multixact_offset_buffers,notify_buffers,num_os_semaphores,oauth_validator_libraries,output_plugin_libraries,parallel_leader_participation,parallel_setup_cost,parallel_tuple_cost,password_encryption,password_expiration_warning_threshold,plan_cache_mode,plpgsql.check_asserts,plpgsql.extra_errors,plpgsql.extra_warnings,plpgsql.print_strict_params,plpgsql.variable_conflict,port,post_auth_delay,pre_auth_delay,primary_conninfo,primary_slot_name,quote_all_identifiers,random_page_cost,recovery_end_command,recovery_init_sync_method,recovery_min_apply_delay,recovery_prefetch,recovery_target,recovery_target_action,recovery_target_inclusive,recovery_target_lsn,recovery_target_name,recovery_target_time,recovery_target_timeline,recovery_target_xid,recursive_worktable_factor,remove_temp_files_after_crash,reserved_connections,restart_after_crash,restore_command,restrict_nonsystem_relation_kind,row_security,scram_iterations,search_path,segment_size,send_abort_for_crash,send_abort_for_kill,seq_page_cost,serializable_buffers,server_encoding,server_version,server_version_num,session_preload_libraries,session_replication_role,shared_buffers,shared_memory_size,shared_memory_size_in_huge_pages,shared_memory_type,shared_preload_libraries,ssl,ssl_ca_file,ssl_cert_file,ssl_ciphers,ssl_crl_dir,ssl_crl_file,ssl_dh_params_file,ssl_groups,ssl_key_file,ssl_library,ssl_max_protocol_version,ssl_min_protocol_version,ssl_passphrase_command,ssl_passphrase_command_supports_reload,ssl_prefer_server_ciphers,ssl_sni,ssl_tls13_ciphers,standard_conforming_strings,statement_timeout,stats_fetch_consistency,subtransaction_buffers,summarize_wal,superuser_reserved_connections,sync_replication_slots,synchronize_seqscans,synchronized_standby_slots,synchronous_commit,synchronous_standby_names,syslog_facility,syslog_ident,syslog_sequence_numbers,syslog_split_messages,tcp_keepalives_count,tcp_keepalives_idle,tcp_keepalives_interval,tcp_user_timeout,temp_buffers,temp_file_limit,temp_tablespaces,timezone_abbreviations,timing_clock_source,trace_connection_negotiation,trace_notify,trace_sort,track_activities,track_activity_query_size,track_commit_timestamp,track_cost_delay_timing,track_counts,track_functions,track_io_timing,track_wal_io_timing,transaction_buffers,transaction_deferrable,transaction_isolation,transaction_read_only,transaction_timeout,transform_null_equals,unix_socket_directories,unix_socket_group,unix_socket_permissions,update_process_title,vacuum_buffer_usage_limit,vacuum_cost_delay,vacuum_cost_limit,vacuum_cost_page_dirty,vacuum_cost_page_hit,vacuum_cost_page_miss,vacuum_failsafe_age,vacuum_freeze_min_age,vacuum_freeze_table_age,vacuum_max_eager_freeze_failure_rate,vacuum_multixact_failsafe_age,vacuum_multixact_freeze_min_age,vacuum_multixact_freeze_table_age,vacuum_truncate,wal_block_size,wal_buffers,wal_compression,wal_consistency_checking,wal_decode_buffer_size,wal_init_zero,wal_keep_size,wal_level,wal_log_hints,wal_receiver_create_temp_slot,wal_receiver_status_interval,wal_receiver_timeout,wal_recycle,wal_retrieve_retry_interval,wal_segment_size,wal_sender_shutdown_timeout,wal_sender_timeout,wal_skip_threshold,wal_summary_keep_time,wal_sync_method,wal_writer_delay,wal_writer_flush_after,work_mem,xmlbinary,xmloption,zero_damaged_pages";

const VIEW_NAMES: &str = "pg_cursors,pg_prepared_statements,pg_prepared_xacts,pg_replication_origin_status,pg_stat_activity,pg_stat_all_indexes,pg_stat_all_tables,pg_stat_archiver,pg_stat_autovacuum_scores,pg_stat_bgwriter,pg_stat_checkpointer,pg_stat_database,pg_stat_database_conflicts,pg_stat_gssapi,pg_stat_io,pg_stat_lock,pg_stat_progress_analyze,pg_stat_progress_basebackup,pg_stat_progress_cluster,pg_stat_progress_copy,pg_stat_progress_create_index,pg_stat_progress_repack,pg_stat_progress_vacuum,pg_stat_recovery,pg_stat_recovery_prefetch,pg_stat_replication,pg_stat_replication_slots,pg_stat_slru,pg_stat_ssl,pg_stat_subscription,pg_stat_subscription_stats,pg_stat_sys_indexes,pg_stat_sys_tables,pg_stat_user_functions,pg_stat_user_indexes,pg_stat_user_tables,pg_stat_wal,pg_stat_wal_receiver,pg_stat_xact_all_tables,pg_stat_xact_sys_tables,pg_stat_xact_user_functions,pg_stat_xact_user_tables,pg_statio_all_indexes,pg_statio_all_sequences,pg_statio_all_tables,pg_statio_sys_indexes,pg_statio_sys_sequences,pg_statio_sys_tables,pg_statio_user_indexes,pg_statio_user_sequences,pg_statio_user_tables,pg_stats,pg_stats_ext,pg_stats_ext_exprs";

const EXTENSION_NAMES: &str = "amcheck:1.5,autoinc:1.0,bloom:1.0,btree_gin:1.4,btree_gist:1.9,citext:1.8,cube:1.5,dblink:1.2,dict_int:1.0,dict_xsyn:1.0,earthdistance:1.2,file_fdw:1.0,fuzzystrmatch:1.2,hstore:1.8,insert_username:1.0,intagg:1.1,intarray:1.5,isn:1.3,lo:1.2,ltree:1.3,moddatetime:1.0,pageinspect:1.13,pg_buffercache:1.7,pg_freespacemap:1.3,pg_logicalinspect:1.0,pg_prewarm:1.2,pg_stash_advice:1.0,pg_stat_statements:1.13,pg_surgery:1.0,pg_trgm:1.6,pg_visibility:1.2,pg_walinspect:1.1,pgcrypto:1.4,pgrowlocks:1.2,pgstattuple:1.5,plpgsql:1.0,postgres_fdw:1.3,refint:1.0,seg:1.4,sslinfo:1.2,tablefunc:1.0,tcn:1.0,tsm_system_rows:1.0,tsm_system_time:1.0,unaccent:1.1";

const HELPER_BODY: &str = r"BEGIN
IF $1 IS NULL OR pg_catalog.octet_length($1) <> 135 OR $1 !~ '^SCRAM-SHA-256[$]600000:[A-Za-z0-9+/]{22}==[$][A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$' THEN
RAISE EXCEPTION USING MESSAGE = 'credential framing refused', ERRCODE = '22023';
END IF;
EXECUTE 'ALTER ROLE credential_target PASSWORD ' || pg_catalog.quote_literal($1);
END";
const OUTER: &str = "SELECT credential_fixture.provision($1::text)";

fn literal(public: &str) -> String {
    format!("'{}'", public.replace('\'', "''"))
}

fn setting(name: &str, expected: &str) -> String {
    format!("current_setting({})={}", literal(name), literal(expected))
}

impl Inventory {
    fn recorded(self) -> String {
        let values: &[(&str, &str)] = match self {
            Self::Trees => &[("debug_pretty_print", "on")],
            Self::Activity => &[("track_activity_query_size", "1024")],
            Self::Counters => &[("compute_query_id", "auto")],
            Self::Destinations => &[
                ("log_directory", "log"),
                ("log_filename", "postgresql-%Y-%m-%d_%H%M%S.log"),
                ("log_file_mode", "0600"),
                ("log_rotation_age", "1440"),
                ("log_rotation_size", "10240"),
                ("log_truncate_on_rotation", "off"),
                ("syslog_facility", "local0"),
                ("syslog_ident", "postgres"),
                ("syslog_sequence_numbers", "on"),
                ("syslog_split_messages", "on"),
            ],
            _ => &[],
        };
        if values.is_empty() {
            return "true".into();
        }
        values
            .iter()
            .map(|(name, value)| {
                format!(
                    "(SELECT setting FROM pg_settings WHERE name={})={}",
                    literal(name),
                    literal(value)
                )
            })
            .collect::<Vec<_>>()
            .join(" AND ")
    }
    fn predicate(self) -> String {
        let group: &[(&str,&str)] = match self {
            Self::Statements => &SUPPRESSIONS[0..1],
            Self::Durations => &SUPPRESSIONS[1..3],
            Self::Samples => &SUPPRESSIONS[3..6],
            Self::Errors => &SUPPRESSIONS[6..9],
            Self::Parameters => &SUPPRESSIONS[9..11],
            Self::Trees => &SUPPRESSIONS[11..15],
            Self::Statistics => &SUPPRESSIONS[15..19],
            Self::OtherLogs => &SUPPRESSIONS[19..24],
            Self::Jit => &[("jit_dump_bitcode","off"),("jit_debugging_support","off")],
            Self::Activity | Self::CrashReport => &[("track_activities","off")],
            Self::Modules => return "(SELECT count(*)=1 AND bool_and(module_name='plpgsql' AND version='19rc1') FROM pg_get_loaded_modules()) AND current_setting('shared_preload_libraries')='' AND current_setting('session_preload_libraries')='' AND current_setting('local_preload_libraries')='' AND (SELECT count(*)=1 AND bool_and(extname='plpgsql' AND extversion='1.0') FROM pg_extension)".into(),
            Self::Explain => return "NOT EXISTS (SELECT FROM pg_settings WHERE name LIKE 'auto_explain.%')".into(),
            Self::StatementExtension => return "NOT EXISTS (SELECT FROM pg_settings WHERE name LIKE 'pg_stat_statements.%') AND to_regclass('pg_stat_statements') IS NULL".into(),
            Self::UnknownFacilities => return format!("(SELECT string_agg(name,',' ORDER BY name) FROM pg_settings)={} AND (SELECT string_agg(name || ':' || default_version,',' ORDER BY name) FROM pg_available_extensions)={}",literal(SETTING_NAMES),literal(EXTENSION_NAMES)),
            Self::Helper => return format!("(SELECT count(*)=1 AND bool_and(p.prosrc={} AND p.provolatile='v' AND NOT p.prosecdef AND NOT p.proisstrict AND p.proparallel='u' AND p.pronargs=1 AND p.pronargdefaults=0 AND p.proargtypes='25'::oidvector AND p.prorettype='void'::regtype AND p.proconfig=ARRAY['search_path=pg_catalog'] AND l.lanname='plpgsql' AND NOT EXISTS (SELECT FROM aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='credential_fixture' AND p.proname='provision') AND current_setting('plpgsql.print_strict_params')='off'",literal(HELPER_BODY)),
            Self::Listings => return "NOT EXISTS (SELECT FROM pg_prepared_statements) AND NOT EXISTS (SELECT FROM pg_cursors)".into(),
            Self::Counters => return format!("NOT EXISTS (SELECT FROM pg_prepared_xacts) AND (SELECT string_agg(viewname,',' ORDER BY viewname) FROM pg_views WHERE schemaname='pg_catalog' AND (viewname LIKE '%stat%' OR viewname LIKE '%cursor%' OR viewname LIKE '%prepared%'))={}",literal(VIEW_NAMES)),
            Self::Destinations => &[("log_destination","stderr"),("logging_collector","off")],
            Self::ConnectionLogs => &[("log_connections",""),("log_disconnections","off"),("log_hostname","off"),("log_line_prefix","")],
            Self::Background => &[("log_checkpoints","on"),("log_autoanalyze_min_duration","10min"),("log_autovacuum_min_duration","10min"),("log_recovery_conflict_waits","off"),("log_startup_progress_interval","10s")],
            Self::Client => &[("client_min_messages","error")],
            Self::Plan => &[("plan_cache_mode","force_generic_plan")],
            // These two rows combine this query with the owned-instance read-back
            // and the source/exit census; they are not SQL proofs of host custody.
            Self::Core | Self::ClientCustody => &[("server_version_num","190000")],
            Self::Wal => return "current_setting('wal_level')='minimal' AND current_setting('effective_wal_level')='minimal' AND NOT EXISTS (SELECT FROM pg_tablespace WHERE pg_tablespace_location(oid)<>'')".into(),
            Self::Archive => return "current_setting('archive_mode')='off' AND current_setting('archive_command')='(disabled)' AND current_setting('archive_library')='' AND (SELECT count(*)=1 AND bool_and(setting='' AND applied AND error IS NULL) FROM pg_file_settings WHERE name='archive_command')".into(),
            Self::Senders => return "current_setting('max_wal_senders')='0' AND NOT EXISTS (SELECT FROM pg_stat_replication)".into(),
            Self::Slots => return "current_setting('max_replication_slots')='0' AND NOT EXISTS (SELECT FROM pg_replication_slots)".into(),
            Self::Replicas => return "NOT pg_is_in_recovery() AND NOT EXISTS (SELECT FROM pg_subscription) AND NOT EXISTS (SELECT FROM pg_stat_wal_receiver)".into(),
            Self::Titles => &[("update_process_title","on")],
        };
        group
            .iter()
            .map(|(name, value)| setting(name, value))
            .collect::<Vec<_>>()
            .join(" AND ")
    }
}

async fn prepare(session: &mut RawSession) -> Result<(), Refusal> {
    for (name, value) in SUPPRESSIONS {
        session.query(&format!("SET {name}={}", literal(value)), false).await?;
    }
    session.query("LOAD 'plpgsql'", false).await?;
    session.query("CREATE SCHEMA credential_fixture", false).await?;
    session
        .query("REVOKE ALL ON SCHEMA credential_fixture FROM PUBLIC", false)
        .await?;
    session.query("CREATE ROLE credential_target NOLOGIN", false).await?;
    session.query(&format!("CREATE FUNCTION credential_fixture.provision(text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog AS {}",literal(HELPER_BODY)),false).await?;
    session
        .query("REVOKE ALL ON FUNCTION credential_fixture.provision(text) FROM PUBLIC", false)
        .await?;
    Ok(())
}

async fn absent_inventory(raw: &mut RawSession) -> Result<(), Refusal> {
    raw.require(
        &Inventory::Helper
            .predicate()
            .replace("p.proname='provision'", "p.proname='absent'")
            .replace("credential_target", "credential_absent"),
    )
    .await
}

async fn inventory(session: &mut RawSession, injected: Option<Inventory>) -> Result<(), Refusal> {
    for row in INVENTORY {
        if injected == Some(row) {
            session.require("false").await?;
        } else {
            session
                .require(&format!("({}) AND ({})", row.predicate(), row.recorded()))
                .await?;
        }
        cli_common::emit(&serde_json::json!({"credential_inventory":format!("{row:?}"),"confirmed":true})).unwrap();
    }
    Ok(())
}

/// Protected inventory parsing admits exactly the public `ParseComplete`, boolean `RowDescription`, boolean `DataRow`, `CommandComplete` and idle `ReadyForQuery` shapes; each shape has an admitted and a refused vector, and unexpected fields remain protected.
/// ´claim:host:credential-raw-public-facts´
/// ´test:unit:public-facts´
#[test]
fn public_facts() {
    for (kind, bytes, expected) in [
        (b'1', b"".as_slice(), Ok(PublicFrame::Parsed)),
        (b'1', b"x".as_slice(), Err(Refusal::Protocol)),
        (
            b'T',
            b"\0\x01ok\0\0\0\0\0\0\0\0\0\0\x10\0\x01\xff\xff\xff\xff\0\0".as_slice(),
            Ok(PublicFrame::Description),
        ),
        (b'T', b"\0\x01bad".as_slice(), Err(Refusal::Protocol)),
        (b'C', b"SET".as_slice(), Err(Refusal::Protocol)),
        (b'C', b"SET\0extra\0".as_slice(), Err(Refusal::Protocol)),
        (b'C', b"".as_slice(), Err(Refusal::Protocol)),
        (b'D', b"\0\x01\0\0\0\x01t".as_slice(), Ok(PublicFrame::Boolean(true))),
        (b'D', b"\0\x01\0\0\0\x01f".as_slice(), Ok(PublicFrame::Boolean(false))),
        (b'Z', b"I".as_slice(), Ok(PublicFrame::Ready)),
        (b'C', b"SET\0".as_slice(), Ok(PublicFrame::Completion)),
        (b'D', b"\0\x01\0\0\0\x05other".as_slice(), Err(Refusal::Protocol)),
        (b'D', b"\0\x01\0\0\0\x01tX".as_slice(), Err(Refusal::Protocol)),
        (b'D', b"\0\x01\0\0\0".as_slice(), Err(Refusal::Protocol)),
        (b'Z', b"T".as_slice(), Err(Refusal::Protocol)),
        (b'E', b"public diagnostic".as_slice(), Err(Refusal::Protocol)),
        (b'K', b"public!!".as_slice(), Err(Refusal::Protocol)),
    ] {
        let frame = wire::Frame {
            kind,
            payload: crate::secret::Buffer::from_bytes(bytes).unwrap(),
        };
        assert_eq!(public_frame(&frame), expected, "assigned public fact framing");
    }
}

/// The protected raw session authenticates with public setup material on both owned standing profiles, suppresses and reads the closed inventory in that backend, pins helper source and attributes, and refuses changed parameter, helper, session-facility and public catalog states. No generated credential, helper execution, sentinel, acceptance or installation property is exercised.
/// ´claim:host:credential-raw-inventory´
/// ´test:unit:raw-inventory´
#[test]
fn raw_inventory() {
    let programs = public_programs();
    let interpreter = std::path::PathBuf::from(std::env::var_os("PN_TEST_PYTHON").expect("registered interpreter"));
    super::core_policy(
        &std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap(),
        &std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap(),
    )
    .unwrap();
    super::lower_core_limit(&interpreter);
    super::core_limits(&std::fs::read_to_string("/proc/self/limits").unwrap()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for (index, profile) in [StandingProfile::Statement, StandingProfile::Stages].into_iter().enumerate() {
        let root = std::env::temp_dir().join(format!("credential-raw-{}-{index}", std::process::id()));
        let mut instance = OwnedInstance::start(&programs, root.clone(), profile);
        runtime.block_on(async {
            let session = super::admitted_connection(&instance).await.unwrap();
            drop(session);
            let mut raw = RawSession::open(&instance).await.expect("raw host authentication");
            raw.require("current_setting('server_version_num')='190000'").await.unwrap();
            for (name, expected) in profile.settings() {
                if name != "archive_command" {
                    raw.require(&setting(name, expected))
                        .await
                        .expect("raw standing state precedes suppressions");
                }
            }
            prepare(&mut raw).await.expect("public helper setup");
            inventory(&mut raw, None)
                .await
                .expect("complete inventory confirmed in issuing session");
            for (name, correct, wrong) in [
                ("log_parameter_max_length", "0", "-1"),
                ("log_parameter_max_length_on_error", "0", "-1"),
                ("plan_cache_mode", "force_generic_plan", "force_custom_plan"),
            ] {
                raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
                assert_eq!(
                    inventory(&mut raw, None).await,
                    Err(Refusal::Inventory),
                    "changed parameter or plan refuses: {name}"
                );
                raw.query(&format!("SET {name}={}", literal(correct)), false).await.unwrap();
            }
            for (change, restore) in [
                ("STABLE", "VOLATILE"),
                ("SECURITY DEFINER", "SECURITY INVOKER"),
                ("STRICT", "CALLED ON NULL INPUT"),
                ("PARALLEL SAFE", "PARALLEL UNSAFE"),
                ("SET search_path=public", "SET search_path=pg_catalog"),
            ] {
                raw.query(&format!("ALTER FUNCTION credential_fixture.provision(text) {change}"), false)
                    .await
                    .unwrap();
                assert_eq!(
                    raw.require(&Inventory::Helper.predicate()).await,
                    Err(Refusal::Inventory),
                    "changed helper attributes refuse: {change}"
                );
                raw.query(&format!("ALTER FUNCTION credential_fixture.provision(text) {restore}"), false)
                    .await
                    .unwrap();
            }
            facility_refusals(&mut raw, &instance).await;
            inventory(&mut raw, None)
                .await
                .expect("restored inventory confirmed before later input");
            for row in INVENTORY {
                assert_eq!(
                    inventory(&mut raw, Some(row)).await,
                    Err(Refusal::Inventory),
                    "assigned inventory row refusal: {row:?}"
                );
            }
            raw.query(&format!("CREATE OR REPLACE FUNCTION credential_fixture.provision(text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog AS {}",literal(&HELPER_BODY.replace("credential_target", "other_target"))),false).await.unwrap();
            assert_eq!(raw.require(&Inventory::Helper.predicate()).await,Err(Refusal::Inventory),"changed stored helper source refuses");
            raw.query(&format!("CREATE OR REPLACE FUNCTION credential_fixture.provision(text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog AS {}",literal(HELPER_BODY)),false).await.unwrap();
            raw.require(&Inventory::Helper.predicate()).await.unwrap();
            assert_eq!(raw.require("missing_public_column").await,Err(Refusal::Server),"failed inventory read-back refuses without diagnostics");
            raw.outer().await.expect("fixed unnamed public Parse admitted without Bind");
            raw.query("LOAD 'auto_explain'",false).await.unwrap();
            assert_eq!(raw.require(&Inventory::Modules.predicate()).await,Err(Refusal::Inventory),"changed loaded module roster refuses");
            assert_eq!(raw.require(&Inventory::Explain.predicate()).await, Err(Refusal::Inventory), "loaded explain facility refuses");
            assert_eq!(raw.require(&Inventory::UnknownFacilities.predicate()).await, Err(Refusal::Inventory), "unknown facility roster refuses");
            raw.query("CREATE EXTENSION pg_stat_statements",false).await.unwrap();
            assert_eq!(raw.require(&Inventory::StatementExtension.predicate()).await, Err(Refusal::Inventory), "present statement statistics view refuses");
            raw.close().await.unwrap();
        });
        instance.finish();
        assert!(!root.exists(), "raw instance removed after shutdown");
    }
}

// Public independent derivation vector, never a generated credential.
// (´[ROOT-rule:observe:credential-store-contract]´)
const PUBLIC_VERIFIER: &[u8] = b"SCRAM-SHA-256$600000:AAECAwQFBgcICQoLDA0ODw==$BG6/sqb6MmuibgKDe5DlkjPxurUg316/oHIioBj66LM=:SeM0pJFLIAn5TIkOu/3be11lr38vXTvN870vLIMdDqw=";
const PUBLIC_PASSWORD: &[u8] = b"public-credential-vector";

// Fixture-only secret boundary: Public vectors exercise the protected parameter copy used by the receiver.
// Caveat: The verifier borrow ends at its bounded copy directly into protected Bind storage; the fixture uses public test material and retains no ordinary view.
// (´[ROOT-cav:observe:secret-host-credential-verifier-parameter]´)
// Justified: The wire parameter copy needs a byte slice and the destination remains protected.
#[allow(clippy::disallowed_methods)]
fn bind_parameter(verifier: &crate::secret::Buffer) -> Result<crate::secret::Buffer, Refusal> {
    let length = u32::try_from(verifier.len()).map_err(|_| Refusal::Framing)?;
    let mut bind = crate::secret::Buffer::new();
    bind.append(&[0, 0, 0, 0, 0, 1]).map_err(|_| Refusal::Framing)?;
    bind.append(&length.to_be_bytes()).map_err(|_| Refusal::Framing)?;
    bind.append(verifier.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-verifier-parameter]´) */))
        .map_err(|_| Refusal::Framing)?;
    bind.append(&[0, 0]).map_err(|_| Refusal::Framing)?;
    Ok(bind)
}

// Fixture-only secret boundary: The protected Bind is sent without an ordinary intermediate frame.
// Caveat: The Bind borrow ends at the protected wire send; only public vectors are supplied by these controls.
// (´[ROOT-cav:observe:secret-host-credential-parameter-send]´)
// Justified: The existing protected wire sender requires a byte slice.
#[allow(clippy::disallowed_methods)]
async fn send_parameter(socket: &mut wire::Socket, bind: &crate::secret::Buffer) -> Result<(), Refusal> {
    wire::send(
        socket,
        b'B',
        bind.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-parameter-send]´) */),
    )
    .await
    .map_err(|_| Refusal::Transport)
}

// Fixture-only secret boundary: Only a constant SQLSTATE class leaves protected error storage.
// Caveat: The error borrow is bounded by the protocol field parse and returns only a constant refusal class; message and context never leave the protected frame.
// (´[ROOT-cav:observe:secret-host-credential-error-class]´)
// Justified: SQLSTATE field classification requires a byte slice.
#[allow(clippy::disallowed_methods)]
fn error_class(frame: &wire::Frame) -> Refusal {
    let bytes = frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-error-class]´) */);
    if frame.kind != b'E' || bytes.last() != Some(&0) {
        return Refusal::Protocol;
    }
    let mut cursor = 0;
    let mut class = None;
    while cursor < bytes.len() {
        let tag = bytes[cursor];
        cursor += 1;
        if tag == 0 {
            return if cursor == bytes.len() {
                class.unwrap_or(Refusal::Protocol)
            } else {
                Refusal::Protocol
            };
        }
        let Some(end) = bytes[cursor..].iter().position(|byte| *byte == 0) else {
            return Refusal::Protocol;
        };
        if tag == b'C' {
            if class.is_some() {
                return Refusal::Protocol;
            }
            class = Some(match &bytes[cursor..cursor + end] {
                b"22023" => Refusal::Framing,
                b"42704" => Refusal::MissingRole,
                _ => Refusal::Server,
            });
        }
        cursor += end + 1;
    }
    Refusal::Protocol
}

// Fixture-only secret boundary: Read-back parsing returns offsets and lengths, not verifier bytes.
// Caveat: The read-back borrow ends at validation of one bounded text field; only its public offset and length leave the parse.
// (´[ROOT-cav:observe:secret-host-credential-readback-parse]´)
// Justified: The protocol field boundary must be checked before a protected copy.
#[allow(clippy::disallowed_methods)]
fn verifier_field(frame: &wire::Frame) -> Result<(usize, usize), Refusal> {
    let bytes = frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-readback-parse]´) */);
    if frame.kind != b'D' || bytes.len() != 141 || bytes[..6] != [0, 1, 0, 0, 0, 135] {
        return Err(Refusal::Protocol);
    }
    Ok((6, 135))
}

// Fixture-only secret boundary: Read-back bytes are copied only to the receiver's protected buffer.
// Caveat: The bounded verifier field borrow ends at a protected-to-protected copy and never becomes an ordinary query result.
// (´[ROOT-cav:observe:secret-host-credential-readback-copy]´)
// Justified: The protected append consumer requires the validated field slice.
#[allow(clippy::disallowed_methods)]
fn copy_verifier(frame: &wire::Frame) -> Result<crate::secret::Buffer, Refusal> {
    let (start, length) = verifier_field(frame)?;
    crate::secret::Buffer::from_bytes(
        &frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-readback-copy]´) */)[start..start + length],
    )
    .map_err(|_| Refusal::Protocol)
}

// Fixture-only secret boundary: Equality exposes no verifier value or timing guarantee.
// Caveat: The expected verifier borrow ends at the receiver's equality expression; only equality over public test material is reported.
// (´[ROOT-cav:observe:secret-host-credential-equality-expected]´)
// Caveat: The stored verifier borrow ends at the receiver's equality expression; no slice is retained and no timing property is claimed.
// (´[ROOT-cav:observe:secret-host-credential-equality-stored]´)
// Justified: Byte equality requires both bounded borrowed slices.
#[allow(clippy::disallowed_methods)]
fn verifier_equal(expected: &crate::secret::Buffer, stored: &crate::secret::Buffer) -> bool {
    expected.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-equality-expected]´) */)
        == stored.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-equality-stored]´) */)
}

// Fixture-only secret boundary: Completed captures enter protected storage directly.
// Caveat: The mutable capture loan ends at bounded acquisition through EOF after the writer ends; no ordinary intermediate holds captured bytes.
// (´[ROOT-cav:observe:secret-host-credential-custody-capture]´)
// Justified: File acquisition requires a mutable destination slice.
#[allow(clippy::disallowed_methods)]
fn capture(path: &std::path::Path) -> Result<crate::secret::Buffer, Refusal> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).map_err(|_| Refusal::Transport)?;
    let length = usize::try_from(file.metadata().map_err(|_| Refusal::Transport)?.len()).map_err(|_| Refusal::Framing)?;
    if length > 16 * 1024 * 1024 {
        return Err(Refusal::Framing);
    }
    let mut buffer = crate::secret::Buffer::with_capacity(length + 1);
    {
        let storage = buffer.expose_storage(/* (´[ROOT-cav:observe:secret-host-credential-custody-capture]´) */);
        file.read_exact(&mut storage[..length]).map_err(|_| Refusal::Transport)?;
        if file.read(&mut storage[length..]).map_err(|_| Refusal::Transport)? != 0 {
            return Err(Refusal::Framing);
        }
    }
    buffer.set_length(length).map_err(|_| Refusal::Framing)?;
    Ok(buffer)
}

// Fixture-only secret boundary: Sentinel searches disclose only presence.
// Caveat: The protected capture or view borrow ends at the public sentinel search and returns only presence, never captured content.
// (´[ROOT-cav:observe:secret-host-credential-custody-search]´)
// Justified: The bounded byte search needs a slice and retains none.
#[allow(clippy::disallowed_methods)]
fn contains(buffer: &crate::secret::Buffer, public: &[u8]) -> bool {
    !public.is_empty()
        && buffer.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-custody-search]´) */).windows(public.len()).any(|window| window == public)
}

impl RawSession {
    async fn rows(&mut self, sql: &str) -> Result<Vec<wire::Frame>, Refusal> {
        let mut public = sql.as_bytes().to_vec();
        public.push(0);
        tokio::time::timeout(Duration::from_secs(600), async {
            wire::send(&mut self.socket, b'Q', &public)
                .await
                .map_err(|_| Refusal::Transport)?;
            let mut rows = Vec::new();
            let mut error = None;
            let mut complete = false;
            loop {
                let frame = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
                match frame.kind {
                    b'T' | b'D' => rows.push(frame),
                    b'E' => error = Some(error_class(&frame)),
                    b'C' if public_frame(&frame)? == PublicFrame::Completion => complete = true,
                    b'Z' if public_frame(&frame)? == PublicFrame::Ready => {
                        return if let Some(error) = error {
                            Err(error)
                        } else if complete {
                            Ok(rows)
                        } else {
                            Err(Refusal::Protocol)
                        };
                    }
                    _ => return Err(Refusal::Protocol),
                }
            }
        })
        .await
        .expect("HANG awaiting protected public statement rows; last state=protected response")
    }

    async fn parameter(&mut self, verifier: &crate::secret::Buffer, absent: bool) -> Result<(), Refusal> {
        tokio::time::timeout(Duration::from_secs(600), async {
            let mut parse = vec![0];
            parse.extend_from_slice(if absent {
                b"SELECT credential_fixture.absent($1::text)"
            } else {
                OUTER.as_bytes()
            });
            parse.extend_from_slice(&[0, 0, 1, 0, 0, 0, 25]);
            wire::send(&mut self.socket, b'P', &parse)
                .await
                .map_err(|_| Refusal::Transport)?;
            send_parameter(&mut self.socket, &bind_parameter(verifier)?).await?;
            wire::send(&mut self.socket, b'E', &[0, 0, 0, 0, 0])
                .await
                .map_err(|_| Refusal::Transport)?;
            wire::send(&mut self.socket, b'S', &[])
                .await
                .map_err(|_| Refusal::Transport)?;
            let mut parsed = false;
            let mut bound = false;
            let mut completed = false;
            let mut error = None;
            loop {
                let frame = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
                match frame.kind {
                    b'1' if !parsed && public_frame(&frame)? == PublicFrame::Parsed => parsed = true,
                    b'2' if parsed && !bound && frame.payload.len() == 0 => bound = true,
                    b'D' if bound => { /* void result remains protected, not interpreted */ }
                    b'C' if bound && public_frame(&frame)? == PublicFrame::Completion => completed = true,
                    b'E' => error = Some(error_class(&frame)),
                    b'Z' if public_frame(&frame)? == PublicFrame::Ready => break,
                    _ => return Err(Refusal::Protocol),
                }
            }
            // The unnamed portal and statement have separate explicit Close messages.
            for target in *b"PS" {
                wire::send(&mut self.socket, b'C', &[target, 0])
                    .await
                    .map_err(|_| Refusal::Transport)?;
            }
            wire::send(&mut self.socket, b'S', &[])
                .await
                .map_err(|_| Refusal::Transport)?;
            for _ in 0..2 {
                let frame = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
                if frame.kind != b'3' || frame.payload.len() != 0 {
                    return Err(Refusal::Protocol);
                }
            }
            let ready = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
            if public_frame(&ready)? != PublicFrame::Ready {
                return Err(Refusal::Protocol);
            }
            if let Some(error) = error {
                Err(error)
            } else if parsed && bound && completed {
                Ok(())
            } else {
                Err(Refusal::Protocol)
            }
        })
        .await
        .expect("HANG awaiting public protected Bind execution and Close; last state=protected protocol")
    }
}

/// Public vectors pin protected Bind framing, bounded verifier parsing and copying, equality-only results, constant error classes, bounded capture acquisition and presence-only searches; helper work factor and verifier length match the derivation constants, without a generator or ordinary response buffer.
/// ´claim:host:credential-public-wire-vectors´
/// ´test:unit:public-wire-vectors´
#[test]
fn public_wire_vectors() {
    assert!(
        HELPER_BODY.contains(&format!("[$]{}:", pn_credential_derivation::MAX_ITERATIONS)),
        "helper work factor equals derivation bound"
    );
    assert_eq!(
        PUBLIC_VERIFIER.len(),
        pn_credential_derivation::VERIFIER_LENGTH,
        "public verifier matches derivation framing"
    );
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let value = crate::secret::Buffer::from_bytes(PUBLIC_VERIFIER).unwrap();
        let bind = bind_parameter(&value).unwrap();
        let (mut socket, mut peer) = wire::fixture_pair();
        send_parameter(&mut socket, &bind).await.unwrap();
        let frame = wire::read(&mut peer).await.unwrap();
        let mut expected = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 135];
        expected.extend_from_slice(PUBLIC_VERIFIER);
        expected.extend_from_slice(&[0, 0]);
        assert_eq!(frame.kind, b'B', "protected parameter frame kind");
        assert_eq!(frame.payload.len(), expected.len(), "protected parameter exact length");
        assert!(contains(&frame.payload, &expected), "protected parameter exact public vector");
    });
    readback_vectors();
    custody_vectors();
}

fn readback_vectors() {
    let mut public = vec![0, 1, 0, 0, 0, 135];
    public.extend_from_slice(PUBLIC_VERIFIER);
    let frame = wire::Frame {
        kind: b'D',
        payload: crate::secret::Buffer::from_bytes(&public).unwrap(),
    };
    assert_eq!(verifier_field(&frame), Ok((6, 135)), "read-back field boundaries");
    let copy = copy_verifier(&frame).unwrap();
    let expected = crate::secret::Buffer::from_bytes(PUBLIC_VERIFIER).unwrap();
    assert!(verifier_equal(&expected, &copy), "protected copy equality");
    assert!(
        !verifier_equal(
            &crate::secret::Buffer::from_bytes(b"different public material").unwrap(),
            &copy
        ),
        "unequal protected buffers refuse"
    );
    for bytes in [&public[..public.len() - 1], b"\0\x01\xff\xff\xff\xff", b"\0\x02\0\0\0\x00"] {
        let invalid = wire::Frame {
            kind: b'D',
            payload: crate::secret::Buffer::from_bytes(bytes).unwrap(),
        };
        assert_eq!(
            verifier_field(&invalid),
            Err(Refusal::Protocol),
            "invalid read-back field refuses"
        );
    }
    for (offset, value) in [(1, 2), (5, 134)] {
        let mut changed = public.clone();
        changed[offset] = value;
        let invalid = wire::Frame {
            kind: b'D',
            payload: crate::secret::Buffer::from_bytes(&changed).unwrap(),
        };
        assert_eq!(
            verifier_field(&invalid),
            Err(Refusal::Protocol),
            "read-back field header refuses"
        );
    }
    let invalid = wire::Frame {
        kind: b'T',
        payload: crate::secret::Buffer::from_bytes(&public).unwrap(),
    };
    assert_eq!(verifier_field(&invalid), Err(Refusal::Protocol), "read-back kind refuses");
    for (bytes, expected) in [
        (b"C\x32\x32\x30\x32\x33\0Mpublic sentinel\0\0".as_slice(), Refusal::Framing),
        (b"C\x34\x32\x37\x30\x34\0\0", Refusal::MissingRole),
        (b"C\x39\x39\x39\x39\x39\0\0", Refusal::Server),
        (b"C\x32\x32\x30\x32\x33\0C\x34\x32\x37\x30\x34\0\0", Refusal::Protocol),
        (b"C\x32\x32\x30\x32\x33", Refusal::Protocol),
    ] {
        assert_eq!(
            error_class(&wire::Frame {
                kind: b'E',
                payload: crate::secret::Buffer::from_bytes(bytes).unwrap()
            }),
            expected,
            "constant SQLSTATE class"
        );
    }
    let mut changed = PUBLIC_VERIFIER.to_vec();
    changed[0] ^= 1;
    assert!(
        !verifier_equal(&crate::secret::Buffer::from_bytes(&changed).unwrap(), &copy),
        "equal-length different verifier refuses"
    );
    custody_file_vector();
}

fn custody_file_vector() {
    let path = std::env::temp_dir().join(format!("credential-public-capture-{}", std::process::id()));
    assert!(!path.exists(), "public capture vector path starts absent");
    std::fs::write(&path, b"before public sentinel after").unwrap();
    let acquired = capture(&path);
    std::fs::remove_file(&path).unwrap();
    let acquired = acquired.unwrap();
    assert!(
        contains(&acquired, b"public sentinel"),
        "protected capture acquisition retains public marker"
    );
    std::fs::File::create(&path).unwrap().set_len(16 * 1024 * 1024 + 1).unwrap();
    let oversized = capture(&path);
    std::fs::remove_file(&path).unwrap();
    assert!(
        matches!(oversized, Err(Refusal::Framing)),
        "oversized public capture refuses before acquisition"
    );
}

fn custody_vectors() {
    let captured = crate::secret::Buffer::from_bytes(b"before public sentinel after").unwrap();
    assert!(
        contains(&captured, b"public sentinel"),
        "presence search detects public marker"
    );
    assert!(
        !contains(&captured, b"absent marker"),
        "presence search rejects absent marker"
    );
    assert!(!contains(&captured, b""), "empty search is not evidence");
    for refusal in [
        Refusal::Transport,
        Refusal::Protocol,
        Refusal::Server,
        Refusal::Inventory,
        Refusal::Framing,
        Refusal::MissingRole,
    ] {
        assert!(
            !format!("{refusal:?}").contains("public sentinel"),
            "constant public refusal formatting"
        );
    }
}

fn search_views(frames: Vec<wire::Frame>) {
    for frame in frames {
        assert!(
            !contains(&frame.payload, PUBLIC_VERIFIER),
            "view contains no public verifier sentinel"
        );
        assert!(
            !contains(&frame.payload, PUBLIC_PASSWORD),
            "view contains no public password sentinel"
        );
    }
}

async fn view_walk(observer: &mut RawSession) {
    for name in VIEW_NAMES.split(',') {
        search_views(
            observer
                .rows(&format!("SELECT row_to_json(public_view) FROM pg_catalog.{name} public_view"))
                .await
                .expect("protected complete view roster walk"),
        );
    }
    search_views(
        observer
            .rows("SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='credential_fixture'")
            .await
            .expect("protected helper source walk"),
    );
}

// The pinned server's titles contain command tags and fixed test identities, not SQL or Bind data.
// This public title check is not protected acquisition of arbitrary process memory.
fn public_titles(instance: &OwnedInstance) {
    for (pid, _) in instance.process_limits() {
        let title = match std::fs::read(format!("/proc/{pid}/cmdline")) {
            Ok(title) => title,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("owned process title read-back refuses: {:?}", error.kind()),
        };
        assert!(
            !title.windows(PUBLIC_VERIFIER.len()).any(|part| part == PUBLIC_VERIFIER),
            "public title contains no verifier sentinel"
        );
        assert!(
            !title.windows(PUBLIC_PASSWORD.len()).any(|part| part == PUBLIC_PASSWORD),
            "public title contains no password sentinel"
        );
    }
}

async fn lock_operation(instance: &OwnedInstance, mut issuer: RawSession, observer: &mut RawSession, absent: bool) -> RawSession {
    tokio::time::timeout(Duration::from_secs(600), async {

    let holder = super::admitted_connection(instance).await.unwrap();
    let witness = super::admitted_connection(instance).await.unwrap();
    let hold = holder.client();
    hold.batch_execute("BEGIN; LOCK TABLE pg_catalog.pg_authid IN SHARE ROW EXCLUSIVE MODE")
        .await
        .unwrap();
    let verifier = crate::secret::Buffer::from_bytes(PUBLIC_VERIFIER).unwrap();
    let execution = tokio::spawn(async move {
        let result = issuer.parameter(&verifier, absent).await;
        (issuer, result)
    });
    let observation = async {
        tokio::time::timeout(Duration::from_secs(600),async {
            loop {
                let rows=witness.client().query("SELECT EXISTS(SELECT FROM pg_locks WHERE relation='pg_authid'::regclass AND mode='RowExclusiveLock' AND NOT granted)",&[]).await.unwrap();
                if rows[0].get::<_,bool>(0) { break; }
                assert!(!execution.is_finished(), "helper cannot complete before observed lock release");
                tokio::task::yield_now().await;
            }
        }).await.expect("HANG awaiting credential helper lock; last state=no ungranted RowExclusiveLock");
        public_titles(instance);
        view_walk(observer).await;
        hold.batch_execute("COMMIT").await.unwrap();
    };
    observation.await;
    let (mut issuer, result) = execution.await.expect("public helper task completes");
    assert_eq!(
        result,
        if absent { Err(Refusal::MissingRole) } else { Ok(()) },
        "assigned lock-held helper outcome"
    );
    issuer
        .require(&Inventory::Listings.predicate())
        .await
        .expect("issuer listings empty after Close");
    view_walk(observer).await;
    issuer
    }).await.expect("HANG awaiting credential lock witness; last state=hold, observe, release or completion")
}

fn client_capture() {
    let root = std::env::temp_dir().join(format!("credential-client-capture-{}", std::process::id()));
    assert!(!root.exists(), "client capture directory starts absent");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700,
        "client capture root confines access"
    );
    let output = std::fs::File::create(root.join("output")).unwrap();
    let error = std::fs::File::create(root.join("error")).unwrap();
    for file in [&output, &error] {
        file.set_permissions(std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            file.metadata().unwrap().permissions().mode() & 0o777,
            0o600,
            "client capture file confines access"
        );
    }
    drop((output, error));
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "credential_fixture::raw::public_mechanism",
            "--exact",
            "--include-ignored",
            "--nocapture",
        ])
        .stdout(std::fs::File::create(root.join("output")).unwrap())
        .stderr(std::fs::File::create(root.join("error")).unwrap())
        .status()
        .expect("public mechanism child starts");
    let output = capture(&root.join("output"));
    let error = capture(&root.join("error"));
    std::fs::remove_dir_all(&root).unwrap();
    let output = output.unwrap();
    let error = error.unwrap();
    assert!(
        status.success(),
        "public mechanism child completed; captures remain protected"
    );
    for captured in [&output, &error] {
        assert!(
            !contains(captured, PUBLIC_VERIFIER),
            "completed client capture contains no public verifier sentinel"
        );
        assert!(
            !contains(captured, PUBLIC_PASSWORD),
            "completed client capture contains no public password sentinel"
        );
    }
}

/// Both pinned helper operations reach an observed catalog lock on each owned profile, public Bind data stays protected through read-back and equality, null, malformed and password-shaped inputs refuse at helper framing, and completed server/client captures, process titles and protected views contain neither public sentinel; client captures have owner-only modes.
/// ´claim:host:credential-public-mechanism´
/// ´test:unit:public-mechanism´
#[test]
fn public_mechanism() {
    if !std::env::args().any(|arg| arg == "--include-ignored") {
        client_capture();
        return;
    }
    let programs = public_programs();
    let interpreter = std::path::PathBuf::from(std::env::var_os("PN_TEST_PYTHON").expect("registered interpreter"));
    super::core_policy(
        &std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap(),
        &std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap(),
    )
    .unwrap();
    super::lower_core_limit(&interpreter);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for (index, profile) in [StandingProfile::Statement, StandingProfile::Stages].into_iter().enumerate() {
        let root = std::env::temp_dir().join(format!("credential-mechanism-{}-{index}", std::process::id()));
        let mut instance = OwnedInstance::start(&programs, root.clone(), profile);
        runtime.block_on(async {
            let mut issuer=RawSession::open(&instance).await.unwrap();
            prepare(&mut issuer).await.unwrap();
            issuer.query(&format!("CREATE FUNCTION credential_fixture.absent(text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog AS {}",literal(&HELPER_BODY.replace("credential_target","credential_absent"))),false).await.unwrap();
            issuer.query("REVOKE ALL ON FUNCTION credential_fixture.absent(text) FROM PUBLIC",false).await.unwrap();
            assert_eq!(absent_inventory(&mut issuer).await, Ok(()), "fixed absent helper metadata confirmed");
            issuer.query("ALTER FUNCTION credential_fixture.absent(text) SECURITY DEFINER",false).await.unwrap();
            assert_eq!(absent_inventory(&mut issuer).await, Err(Refusal::Inventory), "changed absent helper metadata refuses");
            issuer.query("ALTER FUNCTION credential_fixture.absent(text) SECURITY INVOKER",false).await.unwrap();
            assert_eq!(absent_inventory(&mut issuer).await, Ok(()), "restored absent helper metadata confirmed");
            inventory(&mut issuer,None).await.unwrap();
            let mut observer=RawSession::open(&instance).await.unwrap();
            for (name,value) in SUPPRESSIONS { observer.query(&format!("SET {name}={}",literal(value)),false).await.unwrap(); }
            issuer.require(&Inventory::Listings.predicate()).await.unwrap();
            issuer = lock_operation(&instance, issuer, &mut observer, false).await;
            let frames=issuer.rows("SELECT rolpassword FROM pg_authid WHERE rolname='credential_target'").await.unwrap();
            let values=frames.iter().filter(|frame|frame.kind==b'D').collect::<Vec<_>>();
            assert_eq!(values.len(),1,"one protected role read-back");
            let stored=copy_verifier(values[0]).unwrap();
            assert!(verifier_equal(&crate::secret::Buffer::from_bytes(PUBLIC_VERIFIER).unwrap(),&stored),"stored verifier equals public Bind vector");
            assert!(matches!(issuer.rows("SELECT credential_fixture.provision(NULL)").await, Err(Refusal::Framing)), "null parameter refuses at helper framing");
            let malformed = crate::secret::Buffer::from_bytes(&[b'A';135]).unwrap();
            assert_eq!(issuer.parameter(&malformed,false).await, Err(Refusal::Framing), "fixed-length malformed parameter refuses at helper framing");
            let plaintext=crate::secret::Buffer::from_bytes(&[b'a';64]).unwrap();
            assert_eq!(issuer.parameter(&plaintext,false).await,Err(Refusal::Framing),"plaintext provisioning refuses at helper framing");
            issuer = lock_operation(&instance, issuer, &mut observer, true).await;
            observer.close().await.unwrap();issuer.close().await.unwrap();
        });
        instance.stop();
        let log = capture(&root.join("server.log")).unwrap();
        assert!(
            !contains(&log, PUBLIC_VERIFIER),
            "completed server log contains no public verifier sentinel"
        );
        assert!(
            !contains(&log, PUBLIC_PASSWORD),
            "completed server log contains no public password sentinel"
        );
        instance.finish();
        assert!(!root.exists(), "public mechanism instance removed after capture");
    }
}

async fn facility_refusals(raw: &mut RawSession, instance: &OwnedInstance) {
    for (name, wrong, required) in [("log_statement", "all", "none")] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Statements.predicate()).await,
            Err(Refusal::Inventory),
            "facility Statements refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [("log_min_duration_statement", "0", "-1"), ("log_duration", "on", "off")] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Durations.predicate()).await,
            Err(Refusal::Inventory),
            "facility Durations refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [
        ("log_min_duration_sample", "0", "-1"),
        ("log_statement_sample_rate", "1", "0"),
        ("log_transaction_sample_rate", "1", "0"),
    ] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Samples.predicate()).await,
            Err(Refusal::Inventory),
            "facility Samples refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [
        ("log_min_error_statement", "error", "panic"),
        ("log_min_messages", "error", "panic"),
        ("log_error_verbosity", "verbose", "terse"),
    ] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Errors.predicate()).await,
            Err(Refusal::Inventory),
            "facility Errors refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [
        ("debug_print_raw_parse", "on", "off"),
        ("debug_print_parse", "on", "off"),
        ("debug_print_rewritten", "on", "off"),
        ("debug_print_plan", "on", "off"),
    ] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Trees.predicate()).await,
            Err(Refusal::Inventory),
            "facility Trees refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [
        ("log_statement_stats", "on", "off"),
        ("log_parser_stats", "on", "off"),
        ("log_planner_stats", "on", "off"),
        ("log_executor_stats", "on", "off"),
    ] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Statistics.predicate()).await,
            Err(Refusal::Inventory),
            "facility Statistics refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [
        ("log_lock_waits", "on", "off"),
        ("log_lock_failures", "on", "off"),
        ("log_replication_commands", "on", "off"),
        ("log_temp_files", "0", "-1"),
        ("backtrace_functions", "exec_simple_query", ""),
    ] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::OtherLogs.predicate()).await,
            Err(Refusal::Inventory),
            "facility OtherLogs refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    remaining_facility_refusals(raw, instance).await;
}

async fn remaining_facility_refusals(raw: &mut RawSession, instance: &OwnedInstance) {
    for (name, wrong, required) in [("track_activities", "on", "off")] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Activity.predicate()).await,
            Err(Refusal::Inventory),
            "facility Activity refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [("track_activities", "on", "off")] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::CrashReport.predicate()).await,
            Err(Refusal::Inventory),
            "facility CrashReport refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [("client_min_messages", "notice", "error")] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Client.predicate()).await,
            Err(Refusal::Inventory),
            "facility Client refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    for (name, wrong, required) in [("update_process_title", "off", "on")] {
        raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
        assert_eq!(
            raw.require(&Inventory::Titles.predicate()).await,
            Err(Refusal::Inventory),
            "facility Titles refuses changed state: {name}"
        );
        raw.query(&format!("SET {name}={}", literal(required)), false).await.unwrap();
    }
    raw.query("SET debug_pretty_print=off", false).await.unwrap();
    assert_eq!(
        inventory(raw, None).await,
        Err(Refusal::Inventory),
        "recorded parse formatting refuses"
    );
    raw.query("SET debug_pretty_print=on", false).await.unwrap();
    raw.query("SET compute_query_id=off", false).await.unwrap();
    assert_eq!(
        inventory(raw, None).await,
        Err(Refusal::Inventory),
        "recorded query identifier mode refuses"
    );
    raw.query("SET compute_query_id=auto", false).await.unwrap();
    raw.query("PREPARE public_listing AS SELECT true", false).await.unwrap();
    assert_eq!(
        raw.require(&Inventory::Listings.predicate()).await,
        Err(Refusal::Inventory),
        "retained statement listing refuses"
    );
    raw.query("DEALLOCATE public_listing", false).await.unwrap();
    raw.rows("BEGIN; DECLARE public_cursor CURSOR WITH HOLD FOR SELECT 1; COMMIT")
        .await
        .unwrap();
    assert_eq!(
        raw.require(&Inventory::Listings.predicate()).await,
        Err(Refusal::Inventory),
        "retained public cursor refuses"
    );
    raw.query("CLOSE public_cursor", false).await.unwrap();

    // Subscription DDL loads a backend module; keep that public refusal in its own backend.
    let mut catalog = RawSession::open(instance).await.unwrap();
    for (name, value) in SUPPRESSIONS {
        catalog.query(&format!("SET {name}={}", literal(value)), false).await.unwrap();
    }
    catalog.query("CREATE SUBSCRIPTION public_subscription CONNECTION 'dbname=postgres' PUBLICATION public_publication WITH (connect=false, enabled=false, create_slot=false, slot_name=NONE)", false).await.unwrap();
    assert_eq!(
        catalog.require(&Inventory::Replicas.predicate()).await,
        Err(Refusal::Inventory),
        "subscription metadata refuses without a connection"
    );
    catalog.query("DROP SUBSCRIPTION public_subscription", false).await.unwrap();
    catalog.query("SET allow_system_table_mods=on", false).await.unwrap();
    catalog
        .query("CREATE VIEW pg_catalog.pg_stat_fixture_public AS SELECT 1", false)
        .await
        .unwrap();
    assert_eq!(
        catalog.require(&Inventory::Counters.predicate()).await,
        Err(Refusal::Inventory),
        "changed public counter view roster refuses"
    );
    catalog
        .query("DROP VIEW pg_catalog.pg_stat_fixture_public", false)
        .await
        .unwrap();
    catalog.query("SET allow_system_table_mods=off", false).await.unwrap();
    catalog.close().await.unwrap();
}

/// Changed public startup configurations and retained public transaction state refuse at their assigned inventory rows before any Bind; separate instances isolate backend-only settings, recorded inactive defaults, replication capacities and inactive archive configuration, without an archive destination, sender, slot or replica.
/// ´claim:host:credential-public-configuration-refusals´
/// ´test:unit:configuration-refusals´
#[test]
fn configuration_refusals() {
    let programs = public_programs();
    let interpreter = std::path::PathBuf::from(std::env::var_os("PN_TEST_PYTHON").expect("registered interpreter"));
    super::lower_core_limit(&interpreter);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let cases: &[(Inventory, &[(&str, &str)])] = &[
        (Inventory::Jit, &[("jit_debugging_support", "on")]),
        (Inventory::Destinations, &[("log_destination", "stderr,csvlog")]),
        (Inventory::ConnectionLogs, &[("log_disconnections", "on")]),
        (Inventory::Background, &[("log_checkpoints", "off")]),
        (Inventory::Wal, &[("wal_level", "replica")]),
        (Inventory::Archive, &[("archive_command", ":")]),
        (Inventory::Senders, &[("wal_level", "replica"), ("max_wal_senders", "1")]),
        (Inventory::Slots, &[("max_replication_slots", "1")]),
        (Inventory::Counters, &[("max_prepared_transactions", "1")]),
        (Inventory::Activity, &[("track_activity_query_size", "2048")]),
        (Inventory::Destinations, &[("log_directory", "public_unused_log")]),
        (Inventory::Destinations, &[("log_filename", "public-unused-%Y.log")]),
        (Inventory::Destinations, &[("log_file_mode", "0640")]),
        (Inventory::Destinations, &[("log_rotation_age", "2d")]),
        (Inventory::Destinations, &[("log_rotation_size", "20MB")]),
        (Inventory::Destinations, &[("log_truncate_on_rotation", "on")]),
        (Inventory::Destinations, &[("syslog_facility", "local1")]),
        (Inventory::Destinations, &[("syslog_ident", "public_unused")]),
        (Inventory::Destinations, &[("syslog_sequence_numbers", "off")]),
        (Inventory::Destinations, &[("syslog_split_messages", "off")]),
    ];
    for (index, (row, settings)) in cases.iter().enumerate() {
        let root = std::env::temp_dir().join(format!("credential-configuration-{}-{index}", std::process::id()));
        let mut instance = OwnedInstance::configured(&programs, root.clone(), StandingProfile::Statement, settings);
        runtime.block_on(configuration_refusal(&instance, *row));
        instance.finish();
        assert!(!root.exists(), "refused public configuration removed");
    }
}

async fn configuration_refusal(instance: &OwnedInstance, row: Inventory) {
    let mut raw = RawSession::open(instance).await.unwrap();
    prepare(&mut raw).await.unwrap();
    if row == Inventory::Counters {
        raw.rows("BEGIN; PREPARE TRANSACTION 'public_xact'").await.unwrap();
    }
    let result = match row {
        Inventory::Jit => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Jit.predicate(),
                Inventory::Jit.recorded()
            ))
            .await
        }
        Inventory::Destinations => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Destinations.predicate(),
                Inventory::Destinations.recorded()
            ))
            .await
        }
        Inventory::ConnectionLogs => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::ConnectionLogs.predicate(),
                Inventory::ConnectionLogs.recorded()
            ))
            .await
        }
        Inventory::Background => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Background.predicate(),
                Inventory::Background.recorded()
            ))
            .await
        }
        Inventory::Wal => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Wal.predicate(),
                Inventory::Wal.recorded()
            ))
            .await
        }
        Inventory::Archive => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Archive.predicate(),
                Inventory::Archive.recorded()
            ))
            .await
        }
        Inventory::Senders => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Senders.predicate(),
                Inventory::Senders.recorded()
            ))
            .await
        }
        Inventory::Slots => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Slots.predicate(),
                Inventory::Slots.recorded()
            ))
            .await
        }
        Inventory::Activity => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Activity.predicate(),
                Inventory::Activity.recorded()
            ))
            .await
        }
        Inventory::Counters => {
            raw.require(&format!(
                "({}) AND ({})",
                Inventory::Counters.predicate(),
                Inventory::Counters.recorded()
            ))
            .await
        }
        _ => unreachable!("closed public configuration cases"),
    };
    assert_eq!(result, Err(Refusal::Inventory), "configured {row:?} refuses before Bind");
    if row == Inventory::Counters {
        raw.query("ROLLBACK PREPARED 'public_xact'", false).await.unwrap();
    }
    raw.close().await.unwrap();
}

fn public_programs() -> [std::path::PathBuf; 3] {
    let programs = super::server_programs(&std::path::PathBuf::from(
        std::env::var_os("PN_POSTGRESQL_BIN").expect("registered server location"),
    ))
    .unwrap();
    let target = std::fs::read_to_string(
        pn_testkit::runtime_path(pn_testkit::RuntimePath::Workspace("packages/host/postgresql-target.txt")).unwrap(),
    )
    .unwrap();
    let version = std::process::Command::new(&programs[0]).arg("--version").output().unwrap();
    assert!(version.status.success());
    super::server_version(std::str::from_utf8(&version.stdout).unwrap(), &target).unwrap();
    programs
}
