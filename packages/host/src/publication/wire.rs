//! Owned structural decoding; no operation here admits a package.
pub(super) use super::Error;
use pn_epoch::publication::disclosures as d;
pub(super) use pn_interchange::{Array, Map, Value};
use pn_records::numerics::NumericContext;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Context<'a> {
    pub numeric: &'a mut NumericContext,
    pub arithmetic: d::limits::Budget,
}
pub(super) trait Wire: Sized {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, context: &mut Context<'_>) -> Result<Value, Error>;
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(value: &Value, context: &mut Context<'_>) -> Result<Self, Error>;
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write_sequence(values: &[Self], c: &mut Context<'_>) -> Result<Value, Error> {
        values.iter().map(|v| v.write(c)).collect::<Result<Vec<_>, _>>().map(array)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read_sequence(value: &Value, c: &mut Context<'_>) -> Result<Vec<Self>, Error> {
        array_fields(value)?.map(|v| Self::read(v, c)).collect()
    }
}
pub(super) fn array(values: impl IntoIterator<Item = Value>) -> Value {
    Value::Array(Array::new(values))
}
pub(super) fn array_fields(value: &Value) -> Result<std::slice::Iter<'_, Value>, Error> {
    match value {
        Value::Array(v) => Ok(v.as_slice().iter()),
        _ => Err(Error::Shape),
    }
}
pub(super) fn take<T: Wire>(fields: &mut std::slice::Iter<'_, Value>, context: &mut Context<'_>) -> Result<T, Error> {
    T::read(fields.next().ok_or(Error::Shape)?, context)
}
pub(super) fn finish(mut fields: std::slice::Iter<'_, Value>) -> Result<(), Error> {
    if fields.next().is_some() { Err(Error::Shape) } else { Ok(()) }
}
macro_rules! field_write {
    ($value:expr, $c:expr) => {
        $value.write($c)
    };
    ($value:expr, $c:expr, exact) => {
        $crate::publication::scalars::ExactText::write_exact($value, $c)
    };
}
macro_rules! field_read {
    ($fields:expr, $c:expr) => {
        take($fields, $c)
    };
    ($fields:expr, $c:expr, exact) => {
        $crate::publication::scalars::ExactText::read_exact($fields.next().ok_or(Error::Shape)?, $c)
    };
}
pub(super) use {field_read, field_write};
macro_rules! structure {
    ($t:path { $($field:ident $(: $mode:ident)?),* }) => {
        impl Wire for $t {
            /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
            fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
                let Self { $($field),* } = self;
                Ok(array([$($crate::publication::wire::field_write!($field, c $(, $mode)?)?),*]))
            }
            /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
            fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
                let mut fields = array_fields(v)?;
                let result = Self { $($field: $crate::publication::wire::field_read!(&mut fields, c $(, $mode)?)?),* };
                finish(fields)?;
                Ok(result)
            }
        }
    };
}
pub(super) use structure;
macro_rules! newtype {
    ($t:path) => {
        impl Wire for $t {
            /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
            fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
                self.0.write(c)
            }
            /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
            fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
                Ok(Self(Wire::read(v, c)?))
            }
        }
    };
}
pub(super) use newtype;
impl Wire for String {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _: &mut Context<'_>) -> Result<Value, Error> {
        Ok(Value::Text(self.clone().into()))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _: &mut Context<'_>) -> Result<Self, Error> {
        match v {
            Value::Text(t) => Ok(t.as_str().into()),
            _ => Err(Error::Shape),
        }
    }
}
impl Wire for bool {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, _: &mut Context<'_>) -> Result<Value, Error> {
        Ok(Value::Bool(*self))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, _: &mut Context<'_>) -> Result<Self, Error> {
        match v {
            Value::Bool(b) => Ok(*b),
            _ => Err(Error::Shape),
        }
    }
}
macro_rules! integer {
    ($($t:ty),*) => {$(
        impl Wire for $t {
            /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
            fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> { self.to_string().write(c) }
            /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
            fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
                let text = String::read(v,c)?;
                let value: Self = text.parse().map_err(|_| Error::Range)?;
                if value.to_string() != text { return Err(Error::CanonicalNumber); }
                Ok(value)
            }
        }
    )*};
}
integer!(u32, u64, u128, i64);
impl Wire for u8 {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        self.to_string().write(c)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        Self::try_from(u64::read(v, c)?).map_err(|_| Error::Range)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write_sequence(values: &[Self], _: &mut Context<'_>) -> Result<Value, Error> {
        Ok(Value::Bytes(values.to_vec().into()))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read_sequence(v: &Value, _: &mut Context<'_>) -> Result<Vec<Self>, Error> {
        match v {
            Value::Bytes(b) => Ok(b.as_slice().to_vec()),
            _ => Err(Error::Shape),
        }
    }
}
impl Wire for usize {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        u64::try_from(*self).map_err(|_| Error::Range)?.write(c)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        Self::try_from(u64::read(v, c)?).map_err(|_| Error::Range)
    }
}
impl<T: Wire> Wire for Option<T> {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        self.as_ref().map_or(Ok(Value::Null), |x| x.write(c))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        if matches!(v, Value::Null) {
            Ok(None)
        } else {
            T::read(v, c).map(Some)
        }
    }
}
impl<T: Wire> Wire for Box<T> {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        (**self).write(c)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        T::read(v, c).map(Box::new)
    }
}
impl<T: Wire> Wire for Vec<T> {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        T::write_sequence(self, c)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        T::read_sequence(v, c)
    }
}
impl<T: Wire, const N: usize> Wire for [T; N] {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        T::write_sequence(self, c)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        Vec::<T>::read(v, c)?.try_into().map_err(|_| Error::Shape)
    }
}
impl<A: Wire, B: Wire> Wire for (A, B) {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        Ok(array([self.0.write(c)?, self.1.write(c)?]))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut f = array_fields(v)?;
        let r = (take(&mut f, c)?, take(&mut f, c)?);
        finish(f)?;
        Ok(r)
    }
}
impl<A: Wire, B: Wire, C: Wire> Wire for (A, B, C) {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        Ok(array([self.0.write(c)?, self.1.write(c)?, self.2.write(c)?]))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let mut f = array_fields(v)?;
        let r = (take(&mut f, c)?, take(&mut f, c)?, take(&mut f, c)?);
        finish(f)?;
        Ok(r)
    }
}
impl<T: Wire + Ord> Wire for BTreeSet<T> {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        let mut values = self.iter().map(|v| v.write(c)).collect::<Result<Vec<_>, _>>()?;
        values.sort();
        Ok(array(values))
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let fields = array_fields(v)?.as_slice();
        if !fields.windows(2).all(|p| p[0] < p[1]) {
            return Err(Error::Order);
        }
        let result = fields.iter().map(|v| T::read(v, c)).collect::<Result<Self, _>>()?;
        if result.len() != fields.len() {
            return Err(Error::Order);
        }
        Ok(result)
    }
}
impl<K: Wire + Ord, V: Wire> Wire for BTreeMap<K, V> {
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn write(&self, c: &mut Context<'_>) -> Result<Value, Error> {
        let pairs = self
            .iter()
            .map(|(k, v)| Ok((k.write(c)?, v.write(c)?)))
            .collect::<Result<Vec<_>, Error>>()?;
        Map::new(pairs).map(Value::Map).map_err(|_| Error::Order)
    }
    /// Justified: Private structural conversion inherits the complete public codec boundary; recording each nested field again would duplicate the same public disclosure.
    fn read(v: &Value, c: &mut Context<'_>) -> Result<Self, Error> {
        let Value::Map(m) = v else { return Err(Error::Shape) };
        let mut result = Self::new();
        for (k, v) in m.iter() {
            if result.insert(K::read(k, c)?, V::read(v, c)?).is_some() {
                return Err(Error::Order);
            }
        }
        Ok(result)
    }
}

pub(super) fn write_set<T: Wire>(values: &[T], c: &mut Context<'_>) -> Result<Value, Error> {
    let mut encoded = values.iter().map(|v| v.write(c)).collect::<Result<Vec<_>, _>>()?;
    encoded.sort();
    if encoded.windows(2).any(|p| p[0] == p[1]) {
        return Err(Error::Order);
    }
    Ok(array(encoded))
}
pub(super) fn read_set<T: Wire>(v: &Value, c: &mut Context<'_>) -> Result<Vec<T>, Error> {
    let fields = array_fields(v)?.as_slice();
    if !fields.windows(2).all(|p| p[0] < p[1]) {
        return Err(Error::Order);
    }
    fields.iter().map(|v| T::read(v, c)).collect()
}
