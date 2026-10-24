//! Syntax census for (´[ROOT-proposal:observe:enforcement]´).
//! Parsing proves item and helper shape, not full recording or secret flow.

use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use quote::ToTokens;
use serde::Deserialize;
use serde_json::{Value, json};
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{Attribute, Block, Expr, ImplItem, Item, Meta, Signature, Stmt, Token, TraitItem, Visibility};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Deserialize)]
struct Root {
    package: String,
    owner: String,
    path: PathBuf,
}

#[derive(Deserialize)]
struct Request {
    roots: Vec<Root>,
    cfg: BTreeSet<String>,
}

struct Census {
    cfg: BTreeSet<String>,
    functions: Vec<Value>,
    generators: Vec<Value>,
    constants: Vec<Value>,
    types: Vec<Value>,
    seen: BTreeSet<(String, PathBuf)>,
}

fn tokens(value: &impl ToTokens) -> String {
    value.to_token_stream().to_string()
}

fn literal_data(expression: &Expr) -> Option<Value> {
    match expression {
        Expr::Lit(value) => match &value.lit {
            syn::Lit::Str(text) => Some(json!(text.value())),
            _ => None,
        },
        Expr::Array(array) => array
            .elems
            .iter()
            .map(literal_data)
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        Expr::Tuple(tuple) => tuple
            .elems
            .iter()
            .map(literal_data)
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        Expr::Reference(reference) => literal_data(&reference.expr),
        _ => None,
    }
}

fn configured(meta: &Meta, cfg: &BTreeSet<String>) -> Result<bool, Error> {
    match meta {
        Meta::Path(path) => Ok(cfg.contains(&tokens(path))),
        Meta::NameValue(value) => Ok(cfg.contains(&tokens(value).replace(' ', ""))),
        Meta::List(list) => {
            let nested = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens.clone())?;
            let values = nested.iter().map(|m| configured(m, cfg)).collect::<Result<Vec<_>, _>>()?;
            if list.path.is_ident("all") {
                Ok(values.iter().all(|v| *v))
            } else if list.path.is_ident("any") {
                Ok(values.iter().any(|v| *v))
            } else if list.path.is_ident("not") && values.len() == 1 {
                Ok(!values[0])
            } else {
                Err("unsupported cfg expression".into())
            }
        }
    }
}

fn enabled(attrs: &[Attribute], cfg: &BTreeSet<String>) -> Result<bool, Error> {
    for attr in attrs {
        if attr.path().is_ident("cfg") && !configured(&attr.parse_args::<Meta>()?, cfg)? {
            return Ok(false);
        }
        if attr.path().is_ident("cfg_attr") {
            return Err("cfg_attr requires an explicit expansion mapping".into());
        }
    }
    Ok(true)
}

fn helper(block: &Block) -> Option<Value> {
    let bootstrap = block.stmts.first().is_some_and(|statement| {
        matches!(statement, Stmt::Expr(Expr::Call(call), _) if matches!(&*call.func, Expr::Path(path) if path.path.is_ident("install_json_panic_hook")))
    });
    let first = block.stmts.get(if bootstrap { 2 } else { 0 })?;
    let expression = match first {
        Stmt::Local(local) => &*local.init.as_ref()?.expr,
        Stmt::Expr(expr, _) => expr,
        _ => return None,
    };
    let Expr::Call(call) = expression else { return None };
    let Expr::Path(path) = &*call.func else { return None };
    let name = tokens(&path.path).replace(' ', "");
    if !matches!(
        name.as_str(),
        "cli_common::observation::scope" | "crate::observation::scope" | "crate::observe::scope"
    ) {
        return None;
    }
    let Stmt::Local(local) = first else {
        return Some(json!({"invalid":"scoped guard must be bound"}));
    };
    let syn::Pat::Ident(binding) = &local.pat else {
        return Some(json!({"invalid":"scoped guard requires a named local"}));
    };
    let guard = binding.ident.to_string();
    let mut terminal = false;
    for (index, statement) in block.stmts.iter().enumerate().skip(1) {
        if let Stmt::Expr(Expr::MethodCall(call), _) = statement
            && let Expr::Path(receiver) = &*call.receiver
            && receiver.path.is_ident(&guard)
            && matches!(call.method.to_string().as_str(), "finish" | "finish_with")
        {
            if index + 2 < block.stmts.len() || terminal {
                return Some(json!({"invalid":"guard finishes before the terminal result"}));
            }
            if let Some(last) = block.stmts.get(index + 1)
                && !matches!(last, Stmt::Expr(Expr::Path(_), None))
            {
                return Some(json!({"invalid":"binding work follows guard completion"}));
            }
            terminal = true;
        }
    }
    if !terminal {
        return Some(json!({"invalid":"scoped guard lacks a terminal result"}));
    }
    let args: Vec<_> = call
        .args
        .iter()
        .take(3)
        .map(|a| {
            if let Expr::Lit(lit) = a
                && let syn::Lit::Str(s) = &lit.lit
            {
                Some(s.value())
            } else {
                None
            }
        })
        .collect();
    if args.len() != 3 || args.iter().any(Option::is_none) {
        return Some(json!({"invalid":"helper identity must be three string literals"}));
    }
    Some(json!({"helper":name,"owner":args[0],"label":args[1],"item":args[2]}))
}

fn instrumentation(attrs: &[Attribute], body: &Block) -> Result<Option<Value>, Error> {
    let declared: Vec<_> = attrs
        .iter()
        .filter(|a| tokens(a.path()).replace(' ', "") == "tracing::instrument")
        .collect();
    if declared.len() > 1 {
        return Err("duplicate instrumentation attribute".into());
    }
    let Some(attribute) = declared.first() else {
        return Ok(helper(body));
    };
    let options = attribute.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
    let mut fields = serde_json::Map::new();
    let mut result = false;
    for option in options {
        match option {
            Meta::NameValue(value) if value.path.is_ident("name") => {
                if let Expr::Lit(literal) = value.value
                    && let syn::Lit::Str(text) = literal.lit
                {
                    fields.insert("name".into(), json!(text.value()));
                } else {
                    return Err("nonliteral span name".into());
                }
            }
            Meta::List(list) if list.path.is_ident("fields") => {
                for field in Punctuated::<Meta, Token![,]>::parse_terminated.parse2(list.tokens)? {
                    if let Meta::NameValue(value) = field
                        && let Some(name) = value.path.get_ident()
                        && let Expr::Lit(literal) = value.value
                    {
                        let field_value = match literal.lit {
                            syn::Lit::Str(text) => json!(text.value()),
                            syn::Lit::Bool(value) if name == "asynchronous" => json!(value.value),
                            _ => return Err("unreviewed span field expression".into()),
                        };
                        if fields.insert(name.to_string(), field_value).is_some() {
                            return Err("duplicate span field".into());
                        }
                    } else {
                        return Err("unreviewed span field expression".into());
                    }
                }
            }
            Meta::Path(path) if path.is_ident("ret") => result = true,
            _ => return Err("undeclared instrumentation option or argument skip".into()),
        }
    }
    fields.insert("helper".into(), json!("tracing::instrument"));
    fields.insert("records_result".into(), json!(result));
    Ok(Some(Value::Object(fields)))
}

impl Census {
    // Justified: The shared syntax adapter receives the separate identity, signature, body and attribute nodes from functions, methods and trait defaults without cloning them.
    #[allow(clippy::too_many_arguments)]
    fn function(
        &mut self,
        root: &Root,
        path: &Path,
        module: &str,
        parent: &str,
        signature: &Signature,
        body: &Block,
        public: bool,
        attrs: &[Attribute],
    ) -> Result<(), Error> {
        if !enabled(attrs, &self.cfg)? {
            return Ok(());
        }
        let name = format!("{module}{parent}{}", signature.ident);
        let boundary = instrumentation(attrs, body)?;
        let start = body.brace_token.span.open().start();
        let end = body.brace_token.span.close().end();
        self.functions
            .push(json!({"package":root.package,"owner":root.owner,"path":path,"item":name,
            "public":public,"const":signature.constness.is_some(),"async":signature.asyncness.is_some(),
            "signature":tokens(signature),"body":tokens(body),"boundary":boundary,
            "start":{"line":start.line,"column":start.column},"end":{"line":end.line,"column":end.column},
            "attributes":attrs.iter().map(tokens).collect::<Vec<_>>()}));
        Ok(())
    }

    fn file(&mut self, root: &Root, path: &Path, module: &str) -> Result<(), Error> {
        if !self.seen.insert((root.package.clone(), path.to_path_buf())) {
            return Err("duplicate module source".into());
        }
        let parsed = syn::parse_file(&fs::read_to_string(path)?)?;
        if !enabled(&parsed.attrs, &self.cfg)? {
            return Ok(());
        }
        let directory = if matches!(
            path.file_name().and_then(|n| n.to_str()),
            Some("lib.rs" | "main.rs" | "mod.rs")
        ) {
            path.parent().ok_or("module has no parent")?.to_path_buf()
        } else {
            path.with_extension("")
        };
        self.items(root, path, &directory, module, &parsed.items)
    }

    // Justified: This exhaustive syntax dispatch keeps every supported item kind visible in one census boundary.
    #[allow(clippy::too_many_lines)]
    fn items(&mut self, root: &Root, path: &Path, directory: &Path, module: &str, items: &[Item]) -> Result<(), Error> {
        for item in items {
            match item {
                Item::Fn(f) => self.function(
                    root,
                    path,
                    module,
                    "",
                    &f.sig,
                    &f.block,
                    matches!(f.vis, Visibility::Public(_)),
                    &f.attrs,
                )?,
                Item::Mod(m) if enabled(&m.attrs, &self.cfg)? => {
                    let child = format!("{module}{}::", m.ident);
                    if let Some((_, items)) = &m.content {
                        self.items(root, path, &directory.join(m.ident.to_string()), &child, items)?;
                    } else {
                        let explicit = m
                            .attrs
                            .iter()
                            .find(|a| a.path().is_ident("path"))
                            .map(|a| {
                                if let Meta::NameValue(v) = &a.meta
                                    && let Expr::Lit(l) = &v.value
                                    && let syn::Lit::Str(s) = &l.lit
                                {
                                    return Ok(s.value());
                                }
                                Err("invalid module path")
                            })
                            .transpose()?;
                        let child_path = if let Some(p) = explicit {
                            directory.join(p)
                        } else {
                            let direct = directory.join(format!("{}.rs", m.ident));
                            let nested = directory.join(m.ident.to_string()).join("mod.rs");
                            if direct.exists() == nested.exists() {
                                return Err("missing or ambiguous module source".into());
                            }
                            if direct.exists() { direct } else { nested }
                        };
                        self.file(root, &child_path, &child)?;
                    }
                }
                Item::Impl(i) if enabled(&i.attrs, &self.cfg)? => {
                    let parent = if let Some((_, tr, _)) = &i.trait_ {
                        format!("<{} as {}>::", tokens(&i.self_ty), tokens(tr))
                    } else {
                        format!("{}::", tokens(&i.self_ty))
                    };
                    for member in &i.items {
                        if let ImplItem::Fn(f) = member {
                            self.function(
                                root,
                                path,
                                module,
                                &parent,
                                &f.sig,
                                &f.block,
                                i.trait_.is_some() || matches!(f.vis, Visibility::Public(_)),
                                &f.attrs,
                            )?;
                        }
                    }
                }
                Item::Trait(t) if enabled(&t.attrs, &self.cfg)? => {
                    for member in &t.items {
                        if let TraitItem::Fn(f) = member
                            && let Some(body) = &f.default
                        {
                            self.function(
                                root,
                                path,
                                module,
                                &format!("{}::", t.ident),
                                &f.sig,
                                body,
                                matches!(t.vis, Visibility::Public(_)),
                                &f.attrs,
                            )?;
                        }
                    }
                }
                Item::Struct(s) if enabled(&s.attrs, &self.cfg)? => {
                    self.types.push(
                        json!({"package":root.package,"path":path,"item":format!("{module}{}",s.ident),"syntax":tokens(s)}),
                    );
                    self.derives(root, path, module, &s.ident.to_string(), &s.attrs);
                }
                Item::Enum(e) if enabled(&e.attrs, &self.cfg)? => {
                    self.types.push(
                        json!({"package":root.package,"path":path,"item":format!("{module}{}",e.ident),"syntax":tokens(e)}),
                    );
                    self.derives(root, path, module, &e.ident.to_string(), &e.attrs);
                }
                Item::Macro(m) if enabled(&m.attrs, &self.cfg)? => {
                    self.generators
                        .push(json!({"package":root.package,"path":path,"item":module,"kind":"item-macro","syntax":tokens(m)}));
                }
                Item::Const(value)
                    if module == "observation_metrics::"
                        && matches!(
                            value.ident.to_string().as_str(),
                            "STEMS" | "MEASURES" | "OUTCOMES" | "RECORDS_MEASURES" | "HOST_MEASURES"
                        ) =>
                {
                    self.constants.push(json!({"name":value.ident.to_string(),"value":literal_data(&value.expr).ok_or("nonliteral metric declaration")?}));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn derives(&mut self, root: &Root, path: &Path, module: &str, name: &str, attrs: &[Attribute]) {
        for attr in attrs.iter().filter(|a| a.path().is_ident("derive")) {
            self.generators.push(json!({"package":root.package,"path":path,"item":format!("{module}{name}"),"kind":"derive","syntax":tokens(attr)}));
        }
    }
}

fn run() -> Result<Value, Error> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let request: Request = serde_json::from_str(&input)?;
    let mut census = Census {
        cfg: request.cfg,
        functions: Vec::new(),
        generators: Vec::new(),
        constants: Vec::new(),
        types: Vec::new(),
        seen: BTreeSet::new(),
    };
    for root in &request.roots {
        census.file(root, &root.path, "")?;
    }
    Ok(
        json!({"schema":1,"configuration":census.cfg,"functions":census.functions,"generators":census.generators,"metric_constants":census.constants,"types":census.types}),
    )
}

fn main() -> ExitCode {
    cli_common::run_stdout_json_command("observe-census", false, tracing::Level::WARN, run)
}
