//! Value validation + normalization against a parameter's resolved type (DM-04).
//!
//! Validation reports what is wrong; reject or not = caller's decision.
//! Typical: operator values -> strict; device values -> stored as received.

use std::collections::HashMap;

use regex::Regex;

use crate::syntax::{BaseType, Facets, ListFacet, ResolvedType, Size};

/// Why a value does not fit its type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValueError {
    /// Not a valid lexical value of the primitive type.
    #[error("{value:?} is not a valid {ty}")]
    Syntax {
        /// Expected primitive type name.
        ty: &'static str,
        /// Offending value or list item.
        value: String,
    },
    /// Outside every allowed range, or not on a step.
    #[error("{value} is outside the allowed range")]
    Range {
        /// Value as given.
        value: String,
    },
    /// Length outside every allowed size. Chars; bytes for binary types.
    #[error("length {len} is outside the allowed size")]
    Size {
        /// Measured length.
        len: usize,
    },
    /// Not an enumerated value + matches no pattern.
    #[error("{value:?} is not an allowed value")]
    NotAllowed {
        /// Value as given.
        value: String,
    },
    /// Too few or too many items, or list string too long.
    #[error("list with {items} items violates the list constraints")]
    List {
        /// Item count.
        items: usize,
    },
}

/// Compiled `<pattern>` regexes, anchored like XML Schema patterns.
#[derive(Debug, Clone, Default)]
pub(crate) struct Patterns {
    compiled: HashMap<String, Option<Regex>>,
}

impl Patterns {
    pub(crate) fn add(&mut self, pattern: &str) {
        if !self.compiled.contains_key(pattern) {
            // Does not compile -> `None`, skipped in validation (lenient).
            let re = Regex::new(&format!("^(?:{pattern})$")).ok();
            self.compiled.insert(pattern.to_owned(), re);
        }
    }

    /// `None` -> no pattern could be evaluated.
    fn any_match(&self, patterns: &[String], value: &str) -> Option<bool> {
        let mut evaluated = false;
        for p in patterns {
            if let Some(Some(re)) = self.compiled.get(p) {
                evaluated = true;
                if re.is_match(value) {
                    return Some(true);
                }
            }
        }
        evaluated.then_some(false)
    }

    pub(crate) fn failed(&self) -> impl Iterator<Item = &str> {
        self.compiled
            .iter()
            .filter(|(_, re)| re.is_none())
            .map(|(p, _)| p.as_str())
    }
}

fn syntax_err(ty: BaseType, value: &str) -> ValueError {
    ValueError::Syntax {
        ty: ty.as_str(),
        value: value.to_owned(),
    }
}

fn size_ok(sizes: &[Size], len: usize) -> bool {
    let len = len as u64;
    sizes.is_empty()
        || sizes
            .iter()
            .any(|s| s.min.is_none_or(|m| len >= m) && s.max.is_none_or(|m| len <= m))
}

fn parse_integer(ty: BaseType, v: &str) -> Result<i128, ValueError> {
    let n: i128 = v.trim().parse().map_err(|_| syntax_err(ty, v))?;
    let (lo, hi) = match ty {
        BaseType::Int => (i32::MIN as i128, i32::MAX as i128),
        BaseType::UnsignedInt => (0, u32::MAX as i128),
        BaseType::Long => (i64::MIN as i128, i64::MAX as i128),
        _ => (0, u64::MAX as i128),
    };
    if (lo..=hi).contains(&n) {
        Ok(n)
    } else {
        Err(syntax_err(ty, v))
    }
}

fn is_leap(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// `YYYY-MM-DDThh:mm:ss[.f+][Z|(+|-)hh:mm]`; time zone optional.
fn valid_datetime(v: &str) -> bool {
    let b = v.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let s = v.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    ) else {
        return false;
    };
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return false;
    }
    let days = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => return false,
    };
    if d == 0 || d > days || h > 23 || mi > 59 || s > 60 {
        return false;
    }
    let mut rest = &v[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return false;
        }
        rest = &frac[n..];
    }
    match rest.as_bytes() {
        [] | [b'Z'] => true,
        [b'+' | b'-', ..] if rest.len() == 6 && rest.as_bytes()[3] == b':' => {
            matches!((num_str(&rest[1..3]), num_str(&rest[4..6])), (Some(h), Some(m)) if h <= 14 && m <= 59)
        }
        _ => false,
    }
}

fn num_str(s: &str) -> Option<u32> {
    s.bytes()
        .all(|c| c.is_ascii_digit())
        .then(|| s.parse().ok())?
}

/// Decoded byte length of base64, `None` if malformed.
fn base64_len(v: &str) -> Option<usize> {
    let s: Vec<u8> = v.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let body = &s[..s.len() - pad];
    body.iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/')
        .then(|| s.len() / 4 * 3 - pad)
}

fn valid_decimal(v: &str) -> bool {
    let v = v.strip_prefix(['+', '-']).unwrap_or(v);
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    (!int.is_empty() || !frac.is_empty())
        && int.bytes().all(|c| c.is_ascii_digit())
        && frac.bytes().all(|c| c.is_ascii_digit())
}

/// Validate one (non-list) value -> normalized form.
fn check_scalar(
    base: BaseType,
    facets: &Facets,
    patterns: &Patterns,
    v: &str,
) -> Result<String, ValueError> {
    match base {
        BaseType::Boolean => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok("true".into()),
            "false" | "0" => Ok("false".into()),
            _ => Err(syntax_err(base, v)),
        },
        BaseType::Int | BaseType::UnsignedInt | BaseType::Long | BaseType::UnsignedLong => {
            let n = parse_integer(base, v)?;
            let in_range = facets.ranges.is_empty()
                || facets.ranges.iter().any(|r| {
                    r.min.is_none_or(|m| n >= m)
                        && r.max.is_none_or(|m| n <= m)
                        && r.step
                            .is_none_or(|s| s == 0 || (n - r.min.unwrap_or(0)) % i128::from(s) == 0)
                });
            if in_range {
                Ok(n.to_string())
            } else {
                Err(ValueError::Range { value: v.into() })
            }
        }
        BaseType::DateTime => {
            if valid_datetime(v.trim()) {
                Ok(v.trim().to_owned())
            } else {
                Err(syntax_err(base, v))
            }
        }
        BaseType::Base64 => {
            let len = base64_len(v).ok_or_else(|| syntax_err(base, v))?;
            if size_ok(&facets.sizes, len) {
                Ok(v.to_owned())
            } else {
                Err(ValueError::Size { len })
            }
        }
        BaseType::HexBinary => {
            if !v.len().is_multiple_of(2) || !v.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(syntax_err(base, v));
            }
            if size_ok(&facets.sizes, v.len() / 2) {
                Ok(v.to_owned())
            } else {
                Err(ValueError::Size { len: v.len() / 2 })
            }
        }
        BaseType::Decimal => {
            if valid_decimal(v.trim()) {
                Ok(v.trim().to_owned())
            } else {
                Err(syntax_err(base, v))
            }
        }
        BaseType::String => {
            let len = v.chars().count();
            if !size_ok(&facets.sizes, len) {
                return Err(ValueError::Size { len });
            }
            let enum_ok = facets.enumerations.iter().any(|e| e.value == v);
            let constrained = !facets.enumerations.is_empty() || !facets.patterns.is_empty();
            let pattern_ok = patterns.any_match(&facets.patterns, v);
            let allowed = !constrained
                || enum_ok
                // Uncompiled patterns -> no constraint.
                || pattern_ok.unwrap_or(facets.enumerations.is_empty());
            if allowed {
                Ok(v.to_owned())
            } else {
                Err(ValueError::NotAllowed { value: v.into() })
            }
        }
    }
}

fn check_list(list: &ListFacet, len: usize, items: usize) -> Result<(), ValueError> {
    let size_ok = list.size.is_none_or(|s| size_ok(&[s], len));
    let count_ok = list.min_items.is_none_or(|m| items as u64 >= m)
        && list.max_items.is_none_or(|m| items as u64 <= m);
    if size_ok && count_ok {
        Ok(())
    } else {
        Err(ValueError::List { items })
    }
}

/// Validate `value` against `ty` -> normalized form.
/// Normalized: canonical booleans + integers, list items joined by `,`.
pub(crate) fn check(
    ty: &ResolvedType,
    patterns: &Patterns,
    value: &str,
) -> Result<String, ValueError> {
    let Some(list) = &ty.list else {
        return check_scalar(ty.base, &ty.facets, patterns, value);
    };
    let items: Vec<&str> = if value.trim().is_empty() {
        Vec::new()
    } else {
        value.split(',').map(str::trim).collect()
    };
    check_list(list, value.chars().count(), items.len())?;
    let normalized = items
        .iter()
        .map(|item| check_scalar(ty.base, &ty.facets, patterns, item))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(normalized.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::{Enumeration, Range, Status};

    fn ty(base: BaseType) -> ResolvedType {
        ResolvedType {
            base,
            data_type: None,
            list: None,
            facets: Facets::default(),
        }
    }

    fn ok(t: &ResolvedType, v: &str) -> String {
        let mut p = Patterns::default();
        t.facets.patterns.iter().for_each(|x| p.add(x));
        check(t, &p, v).unwrap_or_else(|e| panic!("{v:?}: {e}"))
    }

    fn err(t: &ResolvedType, v: &str) -> ValueError {
        let mut p = Patterns::default();
        t.facets.patterns.iter().for_each(|x| p.add(x));
        check(t, &p, v).expect_err(v)
    }

    #[test]
    fn booleans_normalize() {
        let t = ty(BaseType::Boolean);
        assert_eq!(ok(&t, "1"), "true");
        assert_eq!(ok(&t, "False"), "false");
        assert!(matches!(err(&t, "yes"), ValueError::Syntax { .. }));
    }

    #[test]
    fn integer_widths_and_ranges() {
        assert_eq!(ok(&ty(BaseType::Int), "+007"), "7");
        assert!(matches!(
            err(&ty(BaseType::UnsignedInt), "-1"),
            ValueError::Syntax { .. }
        ));
        assert!(matches!(
            err(&ty(BaseType::Int), "2147483648"),
            ValueError::Syntax { .. }
        ));
        assert_eq!(
            ok(&ty(BaseType::UnsignedLong), "18446744073709551615"),
            "18446744073709551615"
        );

        let mut t = ty(BaseType::Int);
        t.facets.ranges = vec![
            Range {
                min: Some(-1),
                max: Some(-1),
                step: None,
            },
            Range {
                min: Some(0),
                max: Some(100),
                step: Some(5),
            },
        ];
        assert_eq!(ok(&t, "-1"), "-1");
        assert_eq!(ok(&t, "35"), "35");
        assert!(matches!(err(&t, "36"), ValueError::Range { .. }));
        assert!(matches!(err(&t, "105"), ValueError::Range { .. }));
    }

    #[test]
    fn strings_enums_patterns_sizes() {
        let mut t = ty(BaseType::String);
        t.facets.sizes = vec![Size {
            min: None,
            max: Some(17),
        }];
        t.facets.patterns = vec![
            String::new(),
            "([0-9A-Fa-f][0-9A-Fa-f]:){5}([0-9A-Fa-f][0-9A-Fa-f])".into(),
        ];
        assert_eq!(ok(&t, ""), "");
        ok(&t, "00:11:22:aa:bb:CC");
        assert!(matches!(
            err(&t, "00:11:22:aa:bb"),
            ValueError::NotAllowed { .. }
        ));
        assert!(matches!(
            err(&t, "00:11:22:aa:bb:cc:dd"),
            ValueError::Size { len: 20 }
        ));

        let mut e = ty(BaseType::String);
        e.facets.enumerations = ["Up", "Down"]
            .map(|v| Enumeration {
                value: v.into(),
                optional: false,
                read_only: false,
                status: Status::Current,
                version: None,
            })
            .to_vec();
        ok(&e, "Up");
        assert!(matches!(err(&e, "up"), ValueError::NotAllowed { .. }));
        // Size = chars, not bytes.
        let mut s = ty(BaseType::String);
        s.facets.sizes = vec![Size {
            min: None,
            max: Some(2),
        }];
        ok(&s, "한글");
    }

    #[test]
    fn lists() {
        let mut t = ty(BaseType::UnsignedInt);
        t.list = Some(ListFacet {
            min_items: Some(1),
            max_items: Some(3),
            size: None,
        });
        assert_eq!(ok(&t, "1, 2,3"), "1,2,3");
        assert!(matches!(err(&t, ""), ValueError::List { items: 0 }));
        assert!(matches!(err(&t, "1,2,3,4"), ValueError::List { items: 4 }));
        assert!(matches!(err(&t, "1,x"), ValueError::Syntax { .. }));
    }

    #[test]
    fn date_times() {
        let t = ty(BaseType::DateTime);
        for v in [
            "0001-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
            "2024-02-29T12:00:00.123456+09:00",
            "2026-10-03T10:00:00",
        ] {
            ok(&t, v);
        }
        for v in [
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-03 10:00:00",
            "2026-10-03T10:00:00+9",
            "unknown",
        ] {
            assert!(matches!(err(&t, v), ValueError::Syntax { .. }), "{v}");
        }
    }

    #[test]
    fn binary_types() {
        let mut b = ty(BaseType::Base64);
        b.facets.sizes = vec![Size {
            min: None,
            max: Some(4),
        }];
        ok(&b, "AAECAw==");
        assert!(matches!(err(&b, "AAECAwQ="), ValueError::Size { len: 5 }));
        assert!(matches!(err(&b, "AAE"), ValueError::Syntax { .. }));
        let mut h = ty(BaseType::HexBinary);
        h.facets.sizes = vec![Size {
            min: Some(2),
            max: Some(2),
        }];
        ok(&h, "0aFF");
        assert!(matches!(err(&h, "0a"), ValueError::Size { len: 1 }));
        assert!(matches!(err(&h, "0g"), ValueError::Syntax { .. }));
        ok(&ty(BaseType::Decimal), "-12.50");
        assert!(matches!(
            err(&ty(BaseType::Decimal), "1.2.3"),
            ValueError::Syntax { .. }
        ));
    }
}
