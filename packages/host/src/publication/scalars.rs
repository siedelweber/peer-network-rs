//! Exact scalar reconstruction through records' public constructors.
use super::wire::{Context, Error, Value, Wire, array, array_fields, finish, take};
use pn_epoch::publication::disclosures as d;
use pn_records::numerics::{BurnAmount, BurnPerAction, Literal, Numeraire, RecordingEventCost, UnitCost};

fn rational_parts(text: &str) -> (String, String) {
    text.split_once('/')
        .map_or_else(|| (text.into(), "1".into()), |(n, d)| (n.into(), d.into()))
}
fn rational_value(text: &str, c: &mut Context<'_>) -> Result<Value, Error> {
    let value = d::Rational::parse(text, &mut c.arithmetic).map_err(Error::Arithmetic)?;
    let exact = value.exact_string(&mut c.arithmetic).map_err(Error::Arithmetic)?;
    rational_parts(&exact).write(c)
}
fn rational_text(v: &Value, c: &mut Context<'_>) -> Result<String, Error> {
    let (n, den) = <(String, String)>::read(v, c)?;
    let source = format!("{n}/{den}");
    let value = d::Rational::parse(&source, &mut c.arithmetic).map_err(|fault| match fault.kind {
        d::FaultKind::Invalid(d::InvalidCode::Literal | d::InvalidCode::ZeroDenominator) => Error::CanonicalNumber,
        _ => Error::Arithmetic(fault),
    })?;
    let exact = value.exact_string(&mut c.arithmetic).map_err(Error::Arithmetic)?;
    if rational_parts(&exact) != (n, den) {
        return Err(Error::CanonicalNumber);
    }
    Ok(exact)
}
impl Wire for d::Rational {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        let exact = self.exact_string(&mut c.arithmetic).map_err(Error::Arithmetic)?;
        rational_parts(&exact).write(c)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let exact = rational_text(v, c)?;
        Self::parse(&exact, &mut c.arithmetic).map_err(Error::Arithmetic)
    }
}
impl Wire for d::enclosure::Interval {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        Ok(array([self.lower().write(c)?, self.upper().write(c)?]))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let (lo, hi) = Wire::read(v, c)?;
        Self::new(lo, hi, &mut c.arithmetic).map_err(Error::Arithmetic)
    }
}
impl Wire for Literal {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        Ok(array([self.source().to_owned().write(c)?, rational_value(self.exact(), c)?]))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut f = array_fields(v)?;
        let source: String = take(&mut f, c)?;
        let exact = rational_text(f.next().ok_or(Error::Shape)?, c)?;
        finish(f)?;
        let value = c.numeric.literal(&source).map_err(Error::Numeric)?;
        if value.exact() != exact {
            return Err(Error::CanonicalNumber);
        }
        Ok(value)
    }
}
macro_rules! amount {
    ($t:ty,$method:ident) => {
        impl Wire for $t {
            /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
            fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
                Ok(array([
                    rational_value(self.exact(), c)?,
                    self.unit().to_owned().write(c)?,
                ]))
            }
            /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
            fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
                let mut f = array_fields(v)?;
                let exact = rational_text(f.next().ok_or(Error::Shape)?, c)?;
                let unit: String = take(&mut f, c)?;
                finish(f)?;
                let literal = c.numeric.literal(&exact).map_err(Error::Numeric)?;
                c.numeric.$method(&literal, &unit).map_err(Error::Numeric)
            }
        }
    };
}
amount!(BurnAmount, burn);
amount!(BurnPerAction, burn_per_action);
impl Wire for Numeraire {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        Ok(array([self.identity().to_owned().write(c)?, self.amount().write(c)?]))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let (id, amount): (String, BurnPerAction) = Wire::read(v, c)?;
        c.numeric.numeraire(&id, &amount).map_err(Error::Numeric)
    }
}
impl Wire for UnitCost {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        let (exact, denomination, unit, terms) = self.disclosure();
        Ok(array([
            rational_value(exact, c)?,
            denomination.to_owned().write(c)?,
            unit.to_owned().write(c)?,
            terms.to_owned().write(c)?,
        ]))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut f = array_fields(v)?;
        let exact = rational_text(f.next().ok_or(Error::Shape)?, c)?;
        let denomination: String = take(&mut f, c)?;
        let unit: String = take(&mut f, c)?;
        let terms: String = take(&mut f, c)?;
        finish(f)?;
        let literal = c.numeric.literal(&exact).map_err(Error::Numeric)?;
        c.numeric
            .unit_cost(&literal, &denomination, &unit, &terms)
            .map_err(Error::Numeric)
    }
}
impl Wire for RecordingEventCost {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        let (exact, denomination, terms) = self.disclosure();
        Ok(array([
            rational_value(exact, c)?,
            denomination.to_owned().write(c)?,
            terms.to_owned().write(c)?,
        ]))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut f = array_fields(v)?;
        let exact = rational_text(f.next().ok_or(Error::Shape)?, c)?;
        let denomination: String = take(&mut f, c)?;
        let terms: String = take(&mut f, c)?;
        finish(f)?;
        let literal = c.numeric.literal(&exact).map_err(Error::Numeric)?;
        c.numeric
            .recording_cost(&literal, &denomination, &terms)
            .map_err(Error::Numeric)
    }
}

// Numeric spelling is retained alongside a reduced value: replay assertions compare the source,
// while the declared numeric field cannot conceal an inconsistent mathematical value.
pub(super) trait ExactText: Sized {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write_exact(&self, c: &mut Context<'_>) -> Result<Value, Error>;
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read_exact(v: &Value, c: &mut Context<'_>) -> Result<Self, Error>;
}
impl ExactText for String {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write_exact(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        Ok(array([self.write(c)?, rational_value(self, c)?]))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read_exact(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut fields = array_fields(v)?;
        let source: String = take(&mut fields, c)?;
        let asserted = fields.next().ok_or(Error::Shape)?;
        let exact = rational_text(asserted, c)?;
        let value = d::Rational::parse(&source, &mut c.arithmetic).map_err(Error::Arithmetic)?;
        if value.exact_string(&mut c.arithmetic).map_err(Error::Arithmetic)? != exact {
            return Err(Error::CanonicalNumber);
        }
        finish(fields)?;
        Ok(source)
    }
}
impl<T: ExactText> ExactText for Option<T> {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write_exact(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        self.as_ref().map_or(Ok(Value::Null), |v| v.write_exact(c))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read_exact(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        if matches!(v, Value::Null) {
            Ok(None)
        } else {
            T::read_exact(v, c).map(Some)
        }
    }
}
impl<T: ExactText> ExactText for Vec<T> {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write_exact(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        self.iter()
            .map(|v| v.write_exact(c))
            .collect::<Result<Vec<_>, _>>()
            .map(array)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read_exact(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        array_fields(v)?.map(|v| T::read_exact(v, c)).collect()
    }
}
impl<K: Wire + Ord, V: ExactText> ExactText for std::collections::BTreeMap<K, V> {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write_exact(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        let pairs = self
            .iter()
            .map(|(k, v)| Ok((k.write(c)?, v.write_exact(c)?)))
            .collect::<Result<Vec<_>, Error>>()?;
        pn_interchange::Map::new(pairs).map(Value::Map).map_err(|_| Error::Order)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read_exact(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let Value::Map(m) = v else { return Err(Error::Shape) };
        let mut result = Self::new();
        for (k, v) in m.iter() {
            if result.insert(K::read(k, c)?, V::read_exact(v, c)?).is_some() {
                return Err(Error::Order);
            }
        }
        Ok(result)
    }
}
