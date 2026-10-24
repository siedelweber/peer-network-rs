//! Runtime witness for (´[ROOT-inv:observe:noninterference]´).
use cli_common::observation::{BootstrapError, bootstrap};
use pn_records::numerics::{ActionCount, ComparisonLimits, ExactLimits, Floor, NumericContext};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "default".into());
    let guard = match bootstrap(mode != "disabled", false, tracing::Level::INFO) {
        Ok(guard) => Some(guard),
        Err(BootstrapError::Unavailable(_)) => None,
        Err(error @ BootstrapError::Configuration(_)) => {
            let mut record = cli_common::ControlPlaneRecord::usage_error("numeric-observation", "observation_configuration");
            record.message = error.to_string();
            let _ignored = cli_common::emit_control_plane_record(&record);
            return cli_common::CommandExit::Usage.exit_code();
        }
    };
    let mut c = NumericContext::new(ExactLimits::default(), ComparisonLimits::new(100, 100)).unwrap();
    let two = c.literal("2").unwrap();
    let three = c.literal("3").unwrap();
    let zero = c.literal("0").unwrap();
    let negative = c.literal("-1").unwrap();
    let amount = c.burn(&three, "burn").unwrap();
    let nu = c.numeraire("public-numeraire", &amount).unwrap();
    let wall = c.computed(&two).unwrap();
    let price = c.charged_price(&wall, &nu, Floor::RationalThreeThirtySevenths).unwrap();
    let vintage = c.consummate(&price, ActionCount(5), 10).unwrap();
    let refused = [
        c.burn(&negative, "burn").is_err(),
        c.unit_cost(&zero, "USD", "burn", "public-market-terms").is_err(),
        c.charged_price(&wall, &nu, Floor::RidgeImage).is_err(),
    ];
    let exit=if cli_common::emit(&serde_json::json!({"charged":vintage.charged().exact(),"price":price.price().exact(),"numeraire":nu.identity(),"refused":refused})).is_ok(){ExitCode::SUCCESS}else{ExitCode::FAILURE};
    drop(guard);
    if std::env::var_os("PN_TEST_OBSERVATION_RENDEZVOUS").is_some() {
        let mut release = [0];
        let _ignored = std::io::Read::read_exact(&mut std::io::stdin(), &mut release);
    }
    exit
}
