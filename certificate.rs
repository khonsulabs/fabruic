mod certificate {
    //! Creating [`Certificate`]s.
    use std::{
        fmt::{self, Debug, Formatter},
        time::Duration,
    };
    use pkcs8::PrivateKeyDocument;
    use serde::{ser::SerializeTupleStruct, Deserialize, Serialize, Serializer};
    use x509_parser::certificate::X509Certificate;
    use zeroize::Zeroize;
    use crate::{Error, Result};
    /// A public Certificate. You can distribute it freely to peers.
    pub struct Certificate(Vec<u8>);
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for Certificate {
        #[inline]
        fn clone(&self) -> Certificate {
            match *self {
                Certificate(ref __self_0_0) => {
                    Certificate(::core::clone::Clone::clone(&(*__self_0_0)))
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::fmt::Debug for Certificate {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match *self {
                Certificate(ref __self_0_0) => {
                    let debug_trait_builder =
                        &mut ::core::fmt::Formatter::debug_tuple(f, "Certificate");
                    let _ = ::core::fmt::DebugTuple::field(debug_trait_builder, &&(*__self_0_0));
                    ::core::fmt::DebugTuple::finish(debug_trait_builder)
                }
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for Certificate {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<Certificate>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = Certificate;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "tuple struct Certificate",
                        )
                    }
                    #[inline]
                    fn visit_newtype_struct<__E>(
                        self,
                        __e: __E,
                    ) -> _serde::__private::Result<Self::Value, __E::Error>
                    where
                        __E: _serde::Deserializer<'de>,
                    {
                        let __field0: Vec<u8> =
                            match <Vec<u8> as _serde::Deserialize>::deserialize(__e) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                        _serde::__private::Ok(Certificate(__field0))
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<Vec<u8>>(
                            &mut __seq,
                        ) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    0usize,
                                    &"tuple struct Certificate with 1 element",
                                ));
                            }
                        };
                        _serde::__private::Ok(Certificate(__field0))
                    }
                }
                _serde::Deserializer::deserialize_newtype_struct(
                    __deserializer,
                    "Certificate",
                    __Visitor {
                        marker: _serde::__private::PhantomData::<Certificate>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::core::marker::StructuralEq for Certificate {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Eq for Certificate {
        #[inline]
        #[doc(hidden)]
        fn assert_receiver_is_total_eq(&self) -> () {
            {
                let _: ::core::cmp::AssertParamIsEq<Vec<u8>>;
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::hash::Hash for Certificate {
        fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
            match *self {
                Certificate(ref __self_0_0) => ::core::hash::Hash::hash(&(*__self_0_0), state),
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Ord for Certificate {
        #[inline]
        fn cmp(&self, other: &Certificate) -> ::core::cmp::Ordering {
            match *other {
                Certificate(ref __self_1_0) => match *self {
                    Certificate(ref __self_0_0) => {
                        match ::core::cmp::Ord::cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::cmp::Ordering::Equal => ::core::cmp::Ordering::Equal,
                            cmp => cmp,
                        }
                    }
                },
            }
        }
    }
    impl ::core::marker::StructuralPartialEq for Certificate {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialEq for Certificate {
        #[inline]
        fn eq(&self, other: &Certificate) -> bool {
            match *other {
                Certificate(ref __self_1_0) => match *self {
                    Certificate(ref __self_0_0) => (*__self_0_0) == (*__self_1_0),
                },
            }
        }
        #[inline]
        fn ne(&self, other: &Certificate) -> bool {
            match *other {
                Certificate(ref __self_1_0) => match *self {
                    Certificate(ref __self_0_0) => (*__self_0_0) != (*__self_1_0),
                },
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialOrd for Certificate {
        #[inline]
        fn partial_cmp(
            &self,
            other: &Certificate,
        ) -> ::core::option::Option<::core::cmp::Ordering> {
            match *other {
                Certificate(ref __self_1_0) => match *self {
                    Certificate(ref __self_0_0) => {
                        match ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::option::Option::Some(::core::cmp::Ordering::Equal) => {
                                ::core::option::Option::Some(::core::cmp::Ordering::Equal)
                            }
                            cmp => cmp,
                        }
                    }
                },
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for Certificate {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_newtype_struct(__serializer, "Certificate", &self.0)
            }
        }
    };
    impl AsRef<[u8]> for Certificate {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    impl From<Certificate> for Vec<u8> {
        fn from(certificate: Certificate) -> Self {
            certificate.0
        }
    }
    impl Certificate {
        /// Build [`Certificate`] from DER-format. This is not meant as a full
        /// validation of a [`Certificate`], it just offers some sane protections.
        ///
        /// # Errors
        /// - [`Error::ParseCertificate`] if the certificate couldn't be parsed
        /// - [`Error::DanglingCertificate`] if the certificate contained
        ///   uncorrelated bytes
        /// - [`Error::ExpiredCertificate`] if the certificate has expires
        /// - [`Error::DomainCertificate`] if the certificate doesn't contain a
        ///   domain name
        pub fn from_der(certificate: Vec<u8>) -> Result<Self> {
            let (trailing, parsed) = match X509Certificate::from_der(&certificate) {
                Ok((trailing, bytes)) => (trailing, bytes),
                Err(error) => return Err(Error::ParseCertificate { certificate, error }),
            };
            if !trailing.is_empty() {
                return Err(Error::DanglingCertificate {
                    dangling: trailing.to_owned(),
                    certificate,
                });
            }
            if let Some(duration) = parsed.validity().time_to_expiration() {
                if duration <= Duration::from_secs(1_728_000) {}
            } else {
                return Err(Error::ExpiredCertificate(certificate));
            }
            if parsed
                .tbs_certificate
                .subject_alternative_name()
                .filter(|name| !name.1.general_names.is_empty())
                .is_none()
            {
                return Err(Error::DomainCertificate(certificate));
            }
            Ok(Self(certificate))
        }
        /// Build [`Certificate`] from DER-format. This skips the validation from
        /// [`from_der`](Self::from_der), which isn't `unsafe`, but will fail
        /// nonetheless when used on an [`Endpoint`](crate::Endpoint).
        #[must_use]
        pub fn unchecked_from_der(certificate: Vec<u8>) -> Self {
            Self(certificate)
        }
    }
    /// A private Key.
    ///
    /// # Safety
    /// Never give this to anybody.
    #[zeroize(drop)]
    pub struct PrivateKey(Option<Vec<u8>>);
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::clone::Clone for PrivateKey {
        #[inline]
        fn clone(&self) -> PrivateKey {
            match *self {
                PrivateKey(ref __self_0_0) => {
                    PrivateKey(::core::clone::Clone::clone(&(*__self_0_0)))
                }
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for PrivateKey {
            fn deserialize<__D>(__deserializer: __D) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<PrivateKey>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = PrivateKey;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "tuple struct PrivateKey",
                        )
                    }
                    #[inline]
                    fn visit_newtype_struct<__E>(
                        self,
                        __e: __E,
                    ) -> _serde::__private::Result<Self::Value, __E::Error>
                    where
                        __E: _serde::Deserializer<'de>,
                    {
                        let __field0: Option<Vec<u8>> =
                            match <Option<Vec<u8>> as _serde::Deserialize>::deserialize(__e) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            };
                        _serde::__private::Ok(PrivateKey(__field0))
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match match _serde::de::SeqAccess::next_element::<
                            Option<Vec<u8>>,
                        >(&mut __seq)
                        {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(_serde::de::Error::invalid_length(
                                    0usize,
                                    &"tuple struct PrivateKey with 1 element",
                                ));
                            }
                        };
                        _serde::__private::Ok(PrivateKey(__field0))
                    }
                }
                _serde::Deserializer::deserialize_newtype_struct(
                    __deserializer,
                    "PrivateKey",
                    __Visitor {
                        marker: _serde::__private::PhantomData::<PrivateKey>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::core::marker::StructuralEq for PrivateKey {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Eq for PrivateKey {
        #[inline]
        #[doc(hidden)]
        fn assert_receiver_is_total_eq(&self) -> () {
            {
                let _: ::core::cmp::AssertParamIsEq<Option<Vec<u8>>>;
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::hash::Hash for PrivateKey {
        fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
            match *self {
                PrivateKey(ref __self_0_0) => ::core::hash::Hash::hash(&(*__self_0_0), state),
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::Ord for PrivateKey {
        #[inline]
        fn cmp(&self, other: &PrivateKey) -> ::core::cmp::Ordering {
            match *other {
                PrivateKey(ref __self_1_0) => match *self {
                    PrivateKey(ref __self_0_0) => {
                        match ::core::cmp::Ord::cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::cmp::Ordering::Equal => ::core::cmp::Ordering::Equal,
                            cmp => cmp,
                        }
                    }
                },
            }
        }
    }
    impl ::core::marker::StructuralPartialEq for PrivateKey {}
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialEq for PrivateKey {
        #[inline]
        fn eq(&self, other: &PrivateKey) -> bool {
            match *other {
                PrivateKey(ref __self_1_0) => match *self {
                    PrivateKey(ref __self_0_0) => (*__self_0_0) == (*__self_1_0),
                },
            }
        }
        #[inline]
        fn ne(&self, other: &PrivateKey) -> bool {
            match *other {
                PrivateKey(ref __self_1_0) => match *self {
                    PrivateKey(ref __self_0_0) => (*__self_0_0) != (*__self_1_0),
                },
            }
        }
    }
    #[automatically_derived]
    #[allow(unused_qualifications)]
    impl ::core::cmp::PartialOrd for PrivateKey {
        #[inline]
        fn partial_cmp(&self, other: &PrivateKey) -> ::core::option::Option<::core::cmp::Ordering> {
            match *other {
                PrivateKey(ref __self_1_0) => match *self {
                    PrivateKey(ref __self_0_0) => {
                        match ::core::cmp::PartialOrd::partial_cmp(&(*__self_0_0), &(*__self_1_0)) {
                            ::core::option::Option::Some(::core::cmp::Ordering::Equal) => {
                                ::core::option::Option::Some(::core::cmp::Ordering::Equal)
                            }
                            cmp => cmp,
                        }
                    }
                },
            }
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(rust_2018_idioms, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for PrivateKey {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_newtype_struct(__serializer, "PrivateKey", &self.0)
            }
        }
    };
    #[allow(non_upper_case_globals)]
    #[doc(hidden)]
    const _DERIVE_zeroize_Zeroize_FOR_PrivateKey: () = {
        extern crate zeroize;
        impl zeroize::Zeroize for PrivateKey {
            fn zeroize(&mut self) {
                match self {
                    PrivateKey(ref mut __binding_0) => {
                        __binding_0.zeroize();
                    }
                }
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals)]
    const _DERIVE_Drop_FOR_PrivateKey: () = {
        impl Drop for PrivateKey {
            fn drop(&mut self) {
                self.zeroize();
            }
        }
    };
    impl Debug for PrivateKey {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str("[[redacted]]")
        }
    }
    impl PrivateKey {
        /// Build [`PrivateKey`] from DER-format. This is not meant as a full
        /// validation of a [`PrivateKey`], it just offers some sane protections.
        ///
        /// # Errors
        /// [`Error::ParsePrivateKey`] if the certificate couldn't be parsed.
        pub fn from_der(private_key: Vec<u8>) -> Result<Self> {
            if let Err(error) = PrivateKeyDocument::from_der(&private_key) {
                return Err(Error::ParsePrivateKey { private_key, error });
            }
            Ok(Self(Some(private_key)))
        }
        /// Build [`PrivateKey`] from DER-format. This skips the validation from
        /// [`from_der`](Self::from_der), which isn't `unsafe`, but will fail
        /// nonetheless when used on an [`Endpoint`](crate::Endpoint).
        #[must_use]
        pub fn unchecked_from_der(private_key: Vec<u8>) -> Self {
            Self(Some(private_key))
        }
    }
    /// Gives read access to the [`PrivateKey`].
    ///
    /// # Security
    /// This is only dangerous in the sense that you aren't supposed to leak the
    /// [`PrivateKey`]. Make sure to use this carefully!
    pub trait Dangerous {
        /// Returns a [`&[u8]`](slice) to the [`PrivateKey`].
        ///
        /// # Security
        /// This is only dangerous in the sense that you aren't supposed to leak the
        /// [`PrivateKey`]. Make sure to use this carefully!
        #[must_use]
        fn as_ref(private_key: &Self) -> &[u8];
        /// Returns a [`Vec<u8>`] to the [`PrivateKey`].
        ///
        /// # Security
        /// This is only dangerous in the sense that you aren't supposed to leak the
        /// [`PrivateKey`]. Make sure to use this carefully!
        #[must_use]
        fn into(private_key: Self) -> Vec<u8>;
        /// Serialize with [`serde`].
        ///
        /// # Security
        /// This is only dangerous in the sense that you aren't supposed to leak the
        /// [`PrivateKey`]. Make sure to use this carefully!
        ///
        /// # Errors
        /// [`S::Error`](Serializer::Error) if serialization failed.
        fn serialize<S: Serializer>(private_key: &Self, serializer: S) -> Result<S::Ok, S::Error>;
    }
    impl Dangerous for PrivateKey {
        fn as_ref(private_key: &Self) -> &[u8] {
            #[allow(clippy::expect_used)]
            private_key.0.as_deref().expect("value already dropped")
        }
        fn into(mut private_key: Self) -> Vec<u8> {
            #[allow(clippy::expect_used)]
            private_key.0.take().expect("value already dropped")
        }
        fn serialize<S: Serializer>(private_key: &Self, serializer: S) -> Result<S::Ok, S::Error> {
            Serializer::serialize_newtype_struct(serializer, "PrivateKey", &private_key.0)
        }
    }
}
