// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl $crate::encode::Encodable for $thing {
            #[inline]
            fn consensus_encode<S: std::io::Write>(&self, mut s: S) -> Result<usize, $crate::encode::Error> {
                let mut ret = 0;
                $( ret += self.$field.consensus_encode(&mut s)?; )+
                Ok(ret)
            }
        }

        impl $crate::encode::Decodable for $thing {
            #[inline]
            fn consensus_decode<D: std::io::Read>(mut d: D) -> Result<$thing, $crate::encode::Error> {
                Ok($thing {
                    $( $field: $crate::encode::Decodable::consensus_decode(&mut d)?, )+
                })
            }
        }
    );
}

macro_rules! serde_struct_impl {
    ($name:ident, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use std::fmt::{self, Formatter};
                use $crate::serde::de::IgnoredAny;

                #[allow(non_camel_case_types)]
                enum Enum { Unknown__Field, $($fe),* }

                struct EnumVisitor;
                impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                    type Value = Enum;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a field name")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        match v {
                            $(
                            stringify!($fe) => Ok(Enum::$fe)
                            ),*,
                            _ => Ok(Enum::Unknown__Field)
                        }
                    }
                }

                impl<'de> $crate::serde::Deserialize<'de> for Enum {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: ::serde::de::Deserializer<'de>,
                    {
                        deserializer.deserialize_str(EnumVisitor)
                    }
                }

                struct Visitor;

                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("a struct")
                    }

                    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                    where
                        A: $crate::serde::de::MapAccess<'de>,
                    {
                        use $crate::serde::de::Error;

                        $(let mut $fe = None;)*

                        loop {
                            match map.next_key::<Enum>()? {
                                Some(Enum::Unknown__Field) => {
                                    map.next_value::<IgnoredAny>()?;
                                }
                                $(
                                    Some(Enum::$fe) => {
                                        $fe = Some(map.next_value()?);
                                    }
                                )*
                                None => { break; }
                            }
                        }

                        $(
                            let Some($fe) = $fe else {
                                return Err(A::Error::missing_field(stringify!($fe)));
                            };
                        )*

                        let ret = $name {
                            $($fe),*
                        };

                        Ok(ret)
                    }
                }
                // end type defs

                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                use $crate::serde::ser::SerializeStruct;

                // Only used to get the struct length.
                static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                $(
                    st.serialize_field(stringify!($fe), &self.$fe)?;
                )*

                st.end()
            }
        }
    )
}

macro_rules! serde_string_impl {
    ($name:ident, $expecting:expr) => {
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                use ::std::fmt::{self, Formatter};
                use ::std::str::FromStr;

                struct Visitor;
                impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        $name::from_str(v).map_err(E::custom)
                    }

                    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(v)
                    }

                    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                    where
                        E: $crate::serde::de::Error,
                    {
                        self.visit_str(&v)
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                serializer.collect_str(&self)
            }
        }
    };
}

/// A combination of `serde_struct_impl` and `serde_string_impl` where string is
/// used for human-readable serialization and struct is used for
/// non-human-readable serialization.
macro_rules! serde_struct_human_string_impl {
    ($name:ident, $expecting:expr, $($fe:ident),*) => (
        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<$name, D::Error>
            where
                D: $crate::serde::de::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    use ::std::fmt::{self, Formatter};
                    use ::std::str::FromStr;

                    struct Visitor;
                    impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                        type Value = $name;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str($expecting)
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            $name::from_str(v).map_err(E::custom)
                        }

                        fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            self.visit_str(v)
                        }

                        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            self.visit_str(&v)
                        }
                    }

                    deserializer.deserialize_str(Visitor)
                } else {
                    use ::std::fmt::{self, Formatter};
                    use $crate::serde::de::IgnoredAny;

                    #[allow(non_camel_case_types)]
                    enum Enum { Unknown__Field, $($fe),* }

                    struct EnumVisitor;
                    impl<'de> $crate::serde::de::Visitor<'de> for EnumVisitor {
                        type Value = Enum;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str("a field name")
                        }

                        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            match v {
                                $(
                                stringify!($fe) => Ok(Enum::$fe)
                                ),*,
                                _ => Ok(Enum::Unknown__Field)
                            }
                        }
                    }

                    impl<'de> $crate::serde::Deserialize<'de> for Enum {
                        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                        where
                            D: $crate::serde::de::Deserializer<'de>,
                        {
                            deserializer.deserialize_str(EnumVisitor)
                        }
                    }

                    struct Visitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for Visitor {
                        type Value = $name;

                        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                            formatter.write_str("a struct")
                        }

                        fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
                        where
                            V: $crate::serde::de::SeqAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            let length = 0;
                            $(
                                let $fe = seq.next_element()?.ok_or_else(|| {
                                    Error::invalid_length(length, &self)
                                })?;
                                #[allow(unused_variables)]
                                let length = length + 1;
                            )*

                            let ret = $name {
                                $($fe),*
                            };

                            Ok(ret)
                        }

                        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                        where
                            A: $crate::serde::de::MapAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            $(let mut $fe = None;)*

                            loop {
                                match map.next_key::<Enum>()? {
                                    Some(Enum::Unknown__Field) => {
                                        map.next_value::<IgnoredAny>()?;
                                    }
                                    $(
                                        Some(Enum::$fe) => {
                                            $fe = Some(map.next_value()?);
                                        }
                                    )*
                                    None => { break; }
                                }
                            }

                            $(
                                let Some($fe) = $fe else {
                                    return Err(A::Error::missing_field(stringify!($fe)));
                                };
                            )*

                            let ret = $name {
                                $($fe),*
                            };

                            Ok(ret)
                        }
                    }
                    // end type defs

                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    deserializer.deserialize_struct(stringify!($name), FIELDS, Visitor)
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> $crate::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.collect_str(&self)
                } else {
                    use $crate::serde::ser::SerializeStruct;

                    // Only used to get the struct length.
                    static FIELDS: &'static [&'static str] = &[$(stringify!($fe)),*];

                    let mut st = serializer.serialize_struct(stringify!($name), FIELDS.len())?;

                    $(
                        st.serialize_field(stringify!($fe), &self.$fe)?;
                    )*

                    st.end()
                }
            }
        }
    )
}

macro_rules! impl_sha256_midstate_wrapper {
    {
        #[$($type_attrs:meta)*]
        pub struct $ty:ident([u8; 32]);
    } => {
        $(#[$type_attrs])*
        #[derive(Copy, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
        pub struct $ty([u8; 32]);

        impl $ty {
            /// Constructs this wrapper struct from raw bytes.
            pub const fn from_byte_array(inner: [u8; 32]) -> Self {
                Self(inner)
            }

            /// The raw bytes within the wrapper type.
            pub const fn as_byte_array(&self) -> &[u8; 32] {
                &self.0
            }

            /// The raw bytes within the wrapper type.
            pub const fn to_byte_array(self) -> [u8; 32] {
                self.0
            }

            /// (Private) convert a sha256 midstate to an object.
            const fn from_midstate(value: crate::hashes::sha256::Midstate) -> Self {
                Self(value.to_parts().0)
            }
        }

        impl ::std::fmt::Display for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::LowerHex::fmt(&self, f)
            }
        }

        impl ::std::fmt::LowerHex for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                hex::fmt_hex_exact!(f, 32, self.0.iter().rev(), hex::Case::Lower)
            }
        }

        impl ::std::fmt::UpperHex for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                hex::fmt_hex_exact!(f, 32, self.0.iter().rev(), hex::Case::Upper)
            }
        }

        impl ::std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self, f)
            }
        }

        impl ::core::str::FromStr for $ty {
            type Err = hex::DecodeFixedLengthBytesError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut arr = hex::decode_to_array(s)?;
                arr.reverse();
                Ok(Self(arr))
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: serde::Serializer {
                // "cheat" by just copying sha256d serde serialization
                crate::hashes::sha256d::Hash::from_byte_array(self.to_byte_array()).serialize(serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: serde::Deserializer<'de> {
                // "cheat" by just copying sha256d serde serialization
                let hash = crate::hashes::sha256d::Hash::deserialize(deserializer)?;
                Ok(Self::from_byte_array(hash.to_byte_array()))
            }
        }
    }
}

#[cfg(test)]
macro_rules! hex_deserialize(
    ($e:expr) => ({
        use $crate::encode::deserialize;

        fn hex_char(c: char) -> u8 {
            match c {
                '0' => 0,
                '1' => 1,
                '2' => 2,
                '3' => 3,
                '4' => 4,
                '5' => 5,
                '6' => 6,
                '7' => 7,
                '8' => 8,
                '9' => 9,
                'a' | 'A' => 10,
                'b' | 'B' => 11,
                'c' | 'C' => 12,
                'd' | 'D' => 13,
                'e' | 'E' => 14,
                'f' | 'F' => 15,
                x => panic!("Invalid character {} in hex string", x),
            }
        }

        let mut ret = Vec::with_capacity($e.len() / 2);
        let mut byte = 0;
        for (ch, store) in $e.chars().zip([false, true].iter().cycle()) {
            byte = (byte << 4) + hex_char(ch);
            if *store {
                ret.push(byte);
                byte = 0;
            }
        }
        deserialize(&ret).expect("deserialize object")
    });
);

#[cfg(test)]
macro_rules! hex_script(
    ($e:expr) => (crate::Script::from_hex_no_prefix($e).expect("hex decoding"))
);

/// Generates a state machine decoder satisfying the [`crate::encoding::Decoder`] trait.
///
/// This macro creates a decoder that processes input bytes through multiple states,
/// transitioning between states based on decoded data. It automatically generates
/// both the decoder struct and associated error types.
///
/// # Syntax
///
/// ```ignore
/// decoder_state_machine! {
///     /// Documentation for the decoder struct
///     pub struct DecoderName(enum InnerEnumName {
///         Done(TargetType),
///         Errored,
///         StateName {
///             decoder: DecoderType,
///             field1: FieldType1,
///             field2: FieldType2,
///             => transition_function_name(output, ...) -> Result {
///                 // Transition logic that returns Ok(NextState) or Err(error)
///             }
///         },
///         // ... more states
///     });
///
///     /// Documentation for the error struct
///     pub struct ErrorName(enum InnerErrorName {
///         [macro-inserted decoder variants]
///         CustomError1(ErrorType1),
///         CustomError2 { field: ErrorType2 },
///         // ... custom error variants
///     });
/// }
/// ```
///
/// # Generated Code
///
/// The macro generates:
/// - A public decoder struct wrapping a private enum
/// - A private enum with states, Done, and Errored variants
/// - Transition functions for each state
/// - A public error struct wrapping a private error enum
/// - A private error enum with decoder errors and custom variants
/// - `Decoder` trait implementation with `push_bytes`, `end`, and `read_limit` methods
/// - `Decode` impl for the target type
///
/// The macro does **not** generate a `fmt::Display` or `std::error::Error` impl
/// for `ErrorName`, so the user must implement these outside of the macro.
///
/// The variants that the macro inserts into `ErrorName` have the same names
/// as the variants on `InnerEnumName`, and they contain a single value of
/// type `<DecoderType as Decoder>::Error`.
///
/// # State Structure
///
/// Each state must have:
/// - `decoder: SomeDecoderType` - The decoder for this state's data
/// - Optional additional fields to carry state between transitions
/// - A transition function that processes the decoder's output
///
/// # Transition Functions
///
/// Transition functions:
/// - Take the decoder's output as first parameter
/// - Take any additional state fields as subsequent parameters
/// - Return `Result<InnerEnumName, InnerErrorName>`
/// - Are called automatically when the decoder completes
///
/// # Error Handling
///
/// The macro automatically:
/// - Creates error variants for each decoder type
/// - Maps decoder errors to the appropriate variant
///
/// # Example Usage
///
/// ```ignore
/// decoder_state_machine! {
///     /// Decodes a length-prefixed string
///     pub struct StringDecoder(enum StringDecoderInner {
///         Done(String),
///         Errored,
///         ReadLength {
///             decoder: encoding::ArrayDecoder<4>
///             => transition_read_length(length_bytes, ...) -> Result {
///                 let length = u32::from_be_bytes(length_bytes) as usize;
///                 if length > MAX_STRING_LENGTH {
///                     return Err(StringDecoderErrorInner::StringTooLong { length });
///                 }
///                 Ok(StringDecoderInner::ReadData {
///                     decoder: encoding::VecDecoder::new(length),
///                     expected_length: length
///                 })
///             }
///         },
///         ReadData {
///             decoder: encoding::VecDecoder,
///             expected_length: usize
///             => transition_read_data(data, expected_length, ...) -> Result {
///                 if data.len() != expected_length {
///                     return Err(StringDecoderErrorInner::LengthMismatch);
///                 }
///                 let string = String::from_utf8(data)
///                     .map_err(StringDecoderErrorInner::InvalidUtf8)?;
///                 Ok(StringDecoderInner::Done(string))
///             }
///         },
///     });
///
///     /// Errors that can occur during string decoding
///     #[derive(Debug)]
///     pub struct StringDecoderError(enum StringDecoderErrorInner {
///         [macro-inserted decoder variants]
///         StringTooLong { length: usize },
///         LengthMismatch,
///         InvalidUtf8(std::string::FromUtf8Error),
///     });
/// }
/// ```
macro_rules! decoder_state_machine {
    (
        $(#[$($struct_attr:tt)*])*
        pub struct $outer_ty:ident(enum $inner_ty:ident {
            Done($target_ty:ty),
            Errored,
            $(
            $variant:ident {
                decoder: $decoder_ty:ty$(,)?
                $(, $field:ident: $field_ty:ty)*
                => $transition_fn:ident($output:ident, ...) -> Result {
                    $($transition_fn_inner:tt)*
                }
            },
            )*
        });

        $(#[$($error_struct_attr:tt)*])*
        pub struct $error_ty:ident(enum $inner_error_ty:ident {
            [macro-inserted decoder variants]
            $($extra_variants:tt)*
        });
    ) => {
        $(#[$($struct_attr)*])*
        pub struct $outer_ty($inner_ty);

        #[allow(clippy::large_enum_variant)]
        enum $inner_ty {
            $($variant {
                decoder: $decoder_ty
                $(, $field: $field_ty)*
            },)*
            Done($target_ty),
            Errored,
        }

        impl $inner_ty {
            $(
            #[inline]
            #[allow(clippy::unnecessary_wraps)] // returns a Result even if it never returns Err
            fn $transition_fn(
                $output: <$decoder_ty as $crate::encoding::Decoder>::Output
                $(, $field: $field_ty)*
            ) -> Result<Self, $inner_error_ty> {
                $($transition_fn_inner)*
            }
            )*
        }

        $(#[$($error_struct_attr)*])*
        pub struct $error_ty($inner_error_ty);

        $(#[$($error_struct_attr)*])*
        enum $inner_error_ty {
            $(
            $variant(<$decoder_ty as $crate::encoding::Decoder>::Error),
            )*
            $($extra_variants)*
        }

        impl $crate::encoding::Decoder for $outer_ty {
            type Output = $target_ty;
            type Error = $error_ty;

            fn push_bytes(
                &mut self,
                bytes: &mut &[u8],
            ) -> Result<$crate::encoding::DecoderStatus, Self::Error> {
                use $inner_ty as Inner;
                loop {
                    match core::mem::replace(&mut self.0, Inner::Errored) {
                        $(
                        Inner::$variant { mut decoder $(, $field)* } => {
                            if decoder
                                .push_bytes(bytes)
                                .map_err($inner_error_ty::$variant)
                                .map_err($error_ty)?
                                .needs_more()
                            {
                                self.0 = Inner::$variant { decoder $(, $field)* };
                                return Ok($crate::encoding::DecoderStatus::NeedsMore);
                            }

                            let output = decoder.end()
                                .map_err($inner_error_ty::$variant)
                                .map_err($error_ty)?;
                            self.0 = $inner_ty::$transition_fn(output $(, $field)*)
                                .map_err($error_ty)?;
                        }
                        )*
                        Inner::Done(out) => {
                            self.0 = Inner::Done(out);
                            return Ok($crate::encoding::DecoderStatus::Ready);
                        }
                        Inner::Errored => panic!("called push_bytes() on an errored decoder"),

                    }
                }
            }

            fn end(self) -> Result<Self::Output, Self::Error> {
                use $inner_ty as Inner;
                match self.0 {
                    $(
                    Inner::$variant { decoder, .. } => {
                        decoder.end()
                            .map_err($inner_error_ty::$variant)
                            .map_err($error_ty)?;
                        // This unreachable! can be hit by badly behaved decoders where push_bytes()
                        // returns DecoderStatus::NeedMore, but end() returns Ok. In general, end()
                        // should return Ok only if push_bytes has returned DecoderStatus::Ready.
                        unreachable!(
                            "end() succeeded on decoder for {} state, but we did not leave that state",
                            stringify!($variant),
                        )
                    }
                    )*
                    Inner::Done(out) => Ok(out),
                    Inner::Errored => panic!("called end() on an errored decoder"),
                }
            }

            fn read_limit(&self) -> usize {
                use $inner_ty as Inner;
                match self.0 {
                    $(
                    Inner::$variant { ref decoder, .. } => decoder.read_limit(),
                    )*
                    Inner::Done(_) | Inner::Errored => 0,
                }
            }
        }

        impl $crate::encoding::Decode for $target_ty {
            type Decoder = $outer_ty;
        }
    };
}

/// Generates a simple decoder wrapper that converts output from an inner decoder.
///
/// This macro creates a decoder that wraps an existing decoder and applies a conversion
/// function to transform the inner decoder's output into the target type. It's simpler
/// than `decoder_state_machine!` as it only wraps a single decoder without state transitions.
///
/// # Syntax
///
/// There are two invocation patterns:
///
/// ## Direct Error Wrapping
/// ```ignore
/// decoder_newtype! {
///     /// Documentation for the decoder struct
///     pub struct DecoderName(InnerDecoderType);
///
///     /// Documentation for the error struct
///     pub struct ErrorName(InnerErrorName);
///     const ERROR_DISPLAY = "output of the Display::fmt function";
///
///     impl Decode for TargetType {
///         fn convert_inner(output_var) -> Result<_, InnerErrorName> {
///             // Conversion logic -- returns `InnerErrorName` for errors!
///         }
///     }
/// }
/// ```
///
/// In this case `InnerErrorName` must be an already-existing error type.
///
/// ## Error Enum Wrapping
/// ```ignore
/// decoder_newtype! {
///     /// Documentation for the decoder struct
///     pub struct DecoderName(InnerDecoderType);
///
///     /// Documentation for the error struct
///     pub struct ErrorName(enum InnerErrorName {
///         // The first variant must be called Decode and hold the inner decoder type.
///         Decode(InnerDecoderErrorType),
///         // All other variants are free-form.
///         CustomError1(ErrorType1),
///         CustomError2 { field: ErrorType2 },
///         // ... custom error variants
///     });
///
///     impl Decode for TargetType {
///         fn convert_inner(output_var) -> Result<_, ErrorName> {
///             // Conversion logic -- returns `ErrorName` for errors!
///         }
///     }
/// }
/// ```
///
/// In this case `InnerErrorName` will be generated as a private enum by the macro.
///
/// # Generated Code
///
/// The macro generates:
/// - A public decoder struct wrapping the inner decoder
/// - A public error struct wrapping a private error enum
/// - A private error enum with `Decode` variant and custom variants
/// - `Decoder` trait implementation with `push_bytes`, `end`, and `read_limit` methods
/// - `Decode` trait implementation for the target type
///
/// **When using the enum pattern, the macro does not generate a `fmt::Display` or
/// `std::error::Error` impl for `ErrorName`. The user must implement these outside
/// of the macro.** When using the non-enum pattern, both `Display` and `Error` are
/// generated by the macro.
///
/// # Parameters
///
/// - `DecoderName` - The wrapper decoder struct name
/// - `InnerDecoderType` - The existing decoder type to wrap
/// - `ErrorName` - The error struct name
/// - `InnerErrorName` - The private error enum name
/// - `InnerDecoderErrorType` - The error type from the inner decoder
/// - `TargetType` - The final output type after conversion
/// - `convert_inner` - Function that converts inner output to target type
///
/// # Conversion Function
///
/// The conversion function:
/// - Takes the inner decoder's output as its parameter
/// - Returns `Result<TargetType, ErrorName>` for enum pattern, `Result<TargetType, InnerErrorName>`
///   for direct-wrapping pattern.
/// - Is called automatically when the inner decoder completes
/// - Can return custom errors defined in the error enum (enum pattern only)
///
/// # Pattern Selection
///
/// - Use **direct error wrapping** when conversion cannot fail or only needs to propagate the inner decoder's errors
/// - Use **error enum wrapping** when conversion can fail with custom error types
///
/// # Error Handling
///
/// The macro automatically:
/// - Creates a `Decode` variant containing the inner decoder's error
/// - Maps inner decoder errors to the `Decode` variant
/// - Allows custom error variants for conversion failures
///
/// # Example Usage
///
/// ## Direct Error Wrapping
/// ```ignore
/// decoder_newtype! {
///     /// Decoder for the [`TxOut`] type.
///     #[derive(Default)]
///     pub struct TxOutDecoder(Decoder4< crate::confidential::AssetDecoder,
///         crate::confidential::ValueDecoder,
///         crate::confidential::NonceDecoder,
///         crate::script::ScriptDecoder,
///     >);
///
///     /// Decoder error for the [`TxOut`] type.
///     #[derive(Clone, PartialEq, Eq, Debug)]
///     pub struct TxOutDecoderError(Decoder4Error<
///         crate::confidential::AssetDecoderError,
///         crate::confidential::ValueDecoderError,
///         crate::confidential::NonceDecoderError,
///         crate::script::ScriptDecoderError,
///     >);
///     const ERROR_DISPLAY = "error decoding transaction output witness";
///
///     impl Decode for TxOut {
///         fn convert_inner(output) -> Result<_, TxOutDecoderErrorInner> {
///             let (asset, value, nonce, script_pubkey) = output;
///             Ok(TxOut { asset, value, nonce, script_pubkey, witness: TxOutWitness::empty() })
///         }
///     }
/// }
/// ```
///
/// ## Error Enum Wrapping
/// ```ignore
/// decoder_newtype! {
///     /// Decoder for range proofs
///     #[derive(Default)]
///     pub struct Decoder(encoding::ByteVecDecoder);
///
///     /// Decoder error for range proofs
///     #[derive(Clone, PartialEq, Eq, Debug)]
///     pub struct DecoderError(enum DecoderErrorInner {
///         Decode(encoding::ByteVecDecoderError),
///         RangeProof(secp256k1_zkp::Error),
///     });
///
///     impl Decode for RangeProof {
///         fn convert_inner(v) -> Result<_, DecoderError> {
///             RangeProof::from_slice(&v).map_err(DecoderError::RangeProof)
///         }
///     }
/// }
/// ```
macro_rules! decoder_newtype {
    // With directly wrapped inner error
    (
        $(#[$($struct_attr:tt)*])*
        pub struct $outer_ty:ident($inner_ty:ty);

        $(#[$($error_struct_attr:tt)*])*
        pub struct $error_ty:ident($inner_ty_error:ty);

        const ERROR_DISPLAY = $error_display:expr;

        impl Decode for $target_ty:ty {
            fn convert_inner($output:ident) -> Result<_, $error_inner1:ty> {
                $($output_fn_inner:tt)*
            }
        }
    ) => {
        $(#[$($struct_attr)*])*
        pub struct $outer_ty($inner_ty);

        $(#[$($error_struct_attr)*])*
        pub struct $error_ty($inner_ty_error);

        impl core::fmt::Display for $error_ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str($error_display)
            }
        }

        impl std::error::Error for $error_ty {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        impl $crate::encoding::Decoder for $outer_ty {
            type Output = $target_ty;
            type Error = $error_ty;

            fn push_bytes(
                &mut self,
                bytes: &mut &[u8],
            ) -> Result<$crate::encoding::DecoderStatus, Self::Error> {
                self.0
                    .push_bytes(bytes)
                    .map_err($error_ty)
            }

            fn end(self) -> Result<Self::Output, Self::Error> {
                let $output = self.0
                    .end()
                    .map_err($error_ty)?;
                let converted = {
                    $($output_fn_inner)*
                };
                converted.map_err($error_ty)
            }

            fn read_limit(&self) -> usize {
                self.0.read_limit()
            }
        }

        impl $crate::encoding::Decode for $target_ty{
            type Decoder = $outer_ty;
        }
    };
    // With inner error enum
    (
        $(#[$($struct_attr:tt)*])*
        pub struct $outer_ty:ident($inner_ty:ty);

        $(#[$($error_struct_attr:tt)*])*
        pub struct $error_ty:ident(enum $inner_error_ty:ident {
            Decode($inner_ty_error:ty),
            $($extra_variants:tt)*
        });

        impl Decode for $target_ty:ty {
            fn convert_inner($output:ident) -> Result<_, $error_inner1:ty> {
                $($output_fn_inner:tt)*
            }
        }
    ) => {
        $(#[$($struct_attr)*])*
        pub struct $outer_ty($inner_ty);

        $(#[$($error_struct_attr)*])*
        pub struct $error_ty($inner_error_ty);

        $(#[$($error_struct_attr)*])*
        enum $inner_error_ty {
            Decode($inner_ty_error),
            $($extra_variants)*
        }

        impl $crate::encoding::Decoder for $outer_ty {
            type Output = $target_ty;
            type Error = $error_ty;

            fn push_bytes(
                &mut self,
                bytes: &mut &[u8],
            ) -> Result<$crate::encoding::DecoderStatus, Self::Error> {
                self.0
                    .push_bytes(bytes)
                    .map_err($inner_error_ty::Decode)
                    .map_err($error_ty)
            }

            fn end(self) -> Result<Self::Output, Self::Error> {
                let $output = self.0
                    .end()
                    .map_err($inner_error_ty::Decode)
                    .map_err($error_ty)?;
                let converted = {
                    $($output_fn_inner)*
                };
                converted.map_err($error_ty)
            }

            fn read_limit(&self) -> usize {
                self.0.read_limit()
            }
        }

        impl $crate::encoding::Decode for $target_ty{
            type Decoder = $outer_ty;
        }
    };
}
