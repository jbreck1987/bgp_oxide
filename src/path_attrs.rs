// This module will house all the structs and machinery related to Path Attributes (PA)

use std::{
    fmt::Display,
    error::Error,
    cell::RefCell,
};

// Implement a basic PA error
#[derive(Debug, PartialEq)]
struct PathAttrError(String);
impl Display for PathAttrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PathAttrError(msg) = self;
        write!(f, "{}", msg)
    }
}
impl Error for PathAttrError {}
// This Trait is necessary since the size of the data field for eath PA
// is variable. Will be used for creating a trait object for use in containers.
pub(crate) trait PAttr {
    // Bit Fiddling

    fn set_opt_bit(&mut self) {
        // Sets the appropriate bit to encode whether the PA is optional or not
        // RFC 4271; Pg. 16
    }
    fn set_trans_bit(&mut self) {
        // Sets the appropriate bit to encode whether the PA is transitive or not
        // RFC 4271; Pg. 17
    }
    fn set_partial_bit(&mut self) {
         // Sets the appropriate bit to encode whether the PA is Partial or not
         // RFC 4271; Pg. 17
    }
}

pub(crate) struct PathAttr {
    // Attribute Flags
    attr_flags: u8,
    // Attribute Type Code
    attr_type_code: u8,
    attr_len: u8,
    attr_value: Vec<u8>,
    
 }
impl PAttr for PathAttr {
    fn set_opt_bit(&mut self) {
        // Set MSB (network byte order) to 1
        self.attr_flags = self.attr_flags | 1 << 7;
    }
    fn set_trans_bit(&mut self) {
        // Set second MSB (network byte order) to 1
        self.attr_flags = self.attr_flags | 1 << 6;
    }
    fn set_partial_bit(&mut self) {
         // Set third MSB (network byte order) to 1
        self.attr_flags = self.attr_flags | 1 << 5;       
    }
}
impl PathAttr {
    fn new() -> Self {
        // Returns a bare PathAttr instance. This isn't public because all PAs should have
        // a function that builds them as opposed to manually creating them on the fly.
        // new() will only be used privately.
        Self {
            attr_flags: 0,
            attr_type_code: 0,
            attr_len: 0,
            attr_value: Vec::new(),
        }
    }
    pub(crate) fn build_origin(value: u8) -> Result<Self, PathAttrError> {
        // Builds the well-known, mandatory Origin PA
        // RFC 4271; Pg. 18
        match value {
            0 | 1 | 2 => {
                // Build new PA instance
                let mut pa  = Self::new();
                pa.set_trans_bit();
                pa.attr_type_code = 1;
                pa.attr_len = 1;
                pa.attr_value.push(value);
                Ok(pa)
            }
            _ => {
                Err(PathAttrError(String::from("Invalid value, valid values are 0, 1, 2.")))
            }
        }
    }
}

// Extended path attributes give 16 bits to determine the length of the attribute value (in octets)
pub(crate) struct PathAttrExt {
    // Attribute Flags
    attr_flags: u8,
    // Attribute Type Code
    attr_type_code: u8,
    attr_len: u16,
    attr_value: Vec<u8>,
 }
impl PAttr for PathAttrExt {}
impl PathAttrExt {
        fn set_ext_bit(&mut self) {
        // Sets the appropriate bits to encode an Extended Length PA
        // RFC 4271; Pg. 17
        todo!();
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_origin_valid_value() {
        for i in 0..=2 {
            let origin = PathAttr::build_origin(i);
            let cell = RefCell::new(origin);
            match cell.borrow().as_ref() {
                Ok(origin) => {
                    // Only transitive bit should be set since this is a well-known, mandatory (non-optional)
                    // PA. This means the attr flags field should equal 128 in decimal.
                    assert_eq!(64, origin.attr_flags);
                    assert_eq!(1, origin.attr_type_code);
                    assert_eq!(i, origin.attr_value[0]);
                }
                _ => {
                    println!("Expected Ok() for the given values, received and Err()")
                }

            };
        }
    }
    #[test]
    fn build_origin_invalid_value() {
        let origin = PathAttr::build_origin(11);
        let cell = RefCell::new(origin);
        match cell.borrow().as_ref() {
            Ok(_) => {
                panic!("Expected Err() due to incorrect value, got Ok()!")
            }
            Err(e) => {
                assert_eq!(*e, PathAttrError(String::from("Invalid value, valid values are 0, 1, 2.")));
            }
        };
    }
}