#![no_std]

// Everything here must be exactly the same in 32 bit mode and 64 bit mode.

use core::convert::TryInto;

macro_rules! read {
    ($bytes: expr, $offset: expr, $type: ty) => {{
        let start: usize = $offset.try_into().ok()?;
        let end:   usize = start.checked_add(core::mem::size_of::<$type>())?;
        <$type>::from_le_bytes($bytes.get(start..end)?.try_into().ok()?)
    }}
}

trait Readable: Sized {
    fn read(bytes: &[u8], endianness: Endianness) -> Option<Self>;
}

macro_rules! implement_readable {
    ($type: ty) => {
        impl Readable for $type {
            fn read(bytes: &[u8], endianness: Endianness) -> Option<Self> {
                match endianness {
                    Endianness::Little => Some(Self::from_le_bytes(bytes.try_into().ok()?)),
                    Endianness::Big    => Some(Self::from_be_bytes(bytes.try_into().ok()?)),
                }
            }
        }
    };

    ($($type: ty),*) => {
        $( implement_readable! { $type } )*
    };
}

implement_readable! { u8, u16, u32, u64 }
implement_readable! { i8, i16, i32, i64 }

struct Reader<'a> {
    bytes:      &'a [u8],
    endianness: Endianness,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], endianness: Endianness) -> Self {
        Self {
            bytes,
            endianness,
        }
    }

    fn read<T: Readable>(&self, offset: u64) -> Option<T> {
        let start: usize = offset.try_into().ok()?;
        let end:   usize = start.checked_add(core::mem::size_of::<T>())?;

        T::read(self.bytes.get(start..end)?, self.endianness)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Bitness {
    Bits32 = 32,
    Bits64 = 64,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Clone)]
pub struct Elf<'a> {
    bytes:   &'a [u8],
    strings: Option<&'a [u8]>,           

    segment_table:      u64,
    segment_count:      u64,
    segment_entry_size: u64,

    section_table:      u64,
    section_count:      u64,
    section_entry_size: u64,

    base_address: u64,
    entrypoint:   u64,

    bitness:    Bitness,
    endianness: Endianness,
}

#[derive(Clone, Debug)]
pub struct Segment<'a> {
    raw_offset: u64,
    raw_size:   u64,

    pub bytes:     &'a [u8],
    pub virt_addr: u64,
    pub virt_size: u64,
    pub seg_type:  u32,
    pub load:      bool,
    pub read:      bool,
    pub write:     bool,
    pub execute:   bool,
}

#[derive(Clone, Debug)]
pub struct Section<'a> {
    raw_offset: u64,
    raw_size:   u64,

    pub bytes:     &'a [u8],
    pub name:      Option<&'a str>,
    pub virt_addr: u64,
    pub sec_type:  u32,
}

impl<'a> Elf<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.get(0x00..0x04)? != b"\x7fELF" {
            return None;
        }

        let bitness = match bytes.get(0x04)? {
            1 => Bitness::Bits32,
            2 => Bitness::Bits64,
            _ => return None,
        };

        let endianness = match bytes.get(0x05)? {
            1 => Endianness::Little,
            2 => Endianness::Big,
            _ => return None,
        };

        let reader = Reader::new(bytes, endianness);

        let (entrypoint, segment_table, segment_entry_size, segment_count,
             section_table, section_entry_size, section_count, shstrndx) = match bitness {
            Bitness::Bits32 => {
                let entry = read!(bytes, 0x18, u32);

                let phoff      = read!(bytes, 0x1c, u32);
                let phent_size = read!(bytes, 0x2a, u16);
                let phnum      = read!(bytes, 0x2c, u16);

                let shoff      = read!(bytes, 0x20, u32);
                let shent_size = read!(bytes, 0x2e, u16);
                let shnum      = read!(bytes, 0x30, u16);

                let shstrndx = read!(bytes, 0x32, u16);

                (entry as u64, phoff as u64, phent_size as u64, phnum as u64,
                 shoff as u64, shent_size as u64, shnum as u64, shstrndx as u64)
            }
            Bitness::Bits64 => {
                let entry = reader.read::<u64>(0x18)?;

                let phoff      = read!(bytes, 0x20, u64);
                let phent_size = read!(bytes, 0x36, u16);
                let phnum      = read!(bytes, 0x38, u16);

                let shoff      = read!(bytes, 0x28, u64);
                let shent_size = read!(bytes, 0x3a, u16);
                let shnum      = read!(bytes, 0x3c, u16);

                let shstrndx = read!(bytes, 0x3e, u16);

                (entry, phoff, phent_size as u64, phnum as u64, shoff, shent_size as u64,
                 shnum as u64, shstrndx as u64)
            }
        };

        let mut elf = Elf {
            bytes,
            strings: None,

            segment_table,
            segment_count,
            segment_entry_size,

            section_table,
            section_entry_size,
            section_count,

            base_address: 0,
            entrypoint,

            bitness,
            endianness,
        };

        if let Some(string_section) = elf.section_by_index(shstrndx) {
            let strings = Self::get_data(bytes, string_section.raw_offset,
                                         string_section.raw_size);

            elf.strings = strings;
        }

        let mut base_address = None;

        elf.segments(|segment| {
            if !segment.load {
                return;
            }

            let new_base = match base_address {
                Some(base) => core::cmp::min(base, segment.virt_addr),
                None       => segment.virt_addr,
            };

            base_address = Some(new_base);
        })?;

        elf.base_address = base_address?;

        Some(elf)
    }

    fn get_data(data: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
        let start: usize = offset.try_into().ok()?;
        let end:   usize = start.checked_add(size.try_into().ok()?)?;

        data.get(start..end)
    }

    fn get_string(&self, offset: u64) -> Option<&str> {
        if let Some(strings) = self.strings {
            let offset: usize = offset.try_into().ok()?;

            let string = strings.get(offset..)?;
            let null   = string.iter().position(|x| *x == 0)?;
            let string = string.get(..null)?;

            core::str::from_utf8(string).ok()
        } else {
            None
        }
    }

    pub fn section_by_index(&self, index: u64) -> Option<Section> {
        if index >= self.section_count {
            return None;
        }
        
        let entry    = index * self.section_entry_size + self.section_table;
        let sec_type = read!(self.bytes, entry + 0x04, u32);

        let name = self.get_string(read!(self.bytes, entry + 0x00, u32) as u64);

        let (virt_addr, raw_offset, raw_size, flags) = match self.bitness {
            Bitness::Bits32 => {
                let virt_addr = read!(self.bytes, entry + 0x0c, u32);

                let raw_offset = read!(self.bytes, entry + 0x10, u32);
                let raw_size   = read!(self.bytes, entry + 0x14, u32);

                let flags = read!(self.bytes, entry + 0x08, u64);

                (virt_addr as u64, raw_offset as u64, raw_size as u64, flags)
            }
            Bitness::Bits64 => {
                let virt_addr = read!(self.bytes, entry + 0x10, u64);

                let raw_offset = read!(self.bytes, entry + 0x18, u64);
                let raw_size   = read!(self.bytes, entry + 0x20, u64);

                let flags = read!(self.bytes, entry + 0x08, u32);

                (virt_addr, raw_offset, raw_size, flags as u64)
            }
        };


        Some(Section {
            raw_offset,
            raw_size,
            name,
            virt_addr,
            sec_type,
            bytes: Self::get_data(self.bytes, raw_offset, raw_size)?,
        })
    }

    pub fn segment_by_index(&self, index: u64) -> Option<Segment> {
        if index >= self.segment_count {
            return None;
        }
        
        let entry    = index * self.segment_entry_size + self.segment_table;
        let seg_type = read!(self.bytes, entry + 0x00, u32);

        let (virt_addr, virt_size, raw_offset, raw_size, flags) = match self.bitness {
            Bitness::Bits32 => {
                let virt_addr  = read!(self.bytes, entry + 0x08, u32);
                let virt_size  = read!(self.bytes, entry + 0x14, u32);
                let raw_offset = read!(self.bytes, entry + 0x04, u32);
                let raw_size   = read!(self.bytes, entry + 0x10, u32);
                let flags      = read!(self.bytes, entry + 0x18, u32);

                (virt_addr as u64, virt_size as u64, raw_offset as u64, raw_size as u64, flags)
            }
            Bitness::Bits64 => {
                let virt_addr  = read!(self.bytes, entry + 0x10, u64);
                let virt_size  = read!(self.bytes, entry + 0x28, u64);
                let raw_offset = read!(self.bytes, entry + 0x08, u64);
                let raw_size   = read!(self.bytes, entry + 0x20, u64);
                let flags      = read!(self.bytes, entry + 0x04, u32);

                (virt_addr, virt_size, raw_offset, raw_size, flags)
            }
        };

        let load    = seg_type == 1;
        let execute = flags & 1 != 0;
        let write   = flags & 2 != 0;
        let read    = flags & 4 != 0;

        Some(Segment {
            raw_offset,
            raw_size,

            load,
            read,
            write,
            execute,
            virt_addr,
            virt_size,
            seg_type,
            bytes: Self::get_data(self.bytes, raw_offset, raw_size)?,
        })
    }

    pub fn segments(&self, mut callback: impl FnMut(&Segment)) -> Option<()> {
        for index in 0..self.segment_count {
            callback(&self.segment_by_index(index)?);
        }

        Some(())
    }

    pub fn sections(&self, mut callback: impl FnMut(&Section)) -> Option<()> {
        for index in 0..self.section_count {
            callback(&self.section_by_index(index)?);
        }

        Some(())
    }

    pub fn base_address(&self) -> u64 {
        self.base_address
    }

    pub fn entrypoint(&self) -> u64 {
        self.entrypoint
    }

    pub fn bitness(&self) -> Bitness {
        self.bitness
    }

    pub fn endianness(&self) -> Endianness {
        self.endianness
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::println;

    #[test]
    fn test() {
        let bytes = std::fs::read("/usr/bin/sh").unwrap();
        let elf   = Elf::parse(&bytes).unwrap();

        println!("Bitness:      {}.",   elf.bitness() as usize);
        println!("Base address: {:x}.", elf.base_address());
        println!("Entrypoint:   {:x}.", elf.entrypoint());

        elf.segments(|segment| {
            let mut r = '-';
            let mut w = '-';
            let mut x = '-';

            if segment.read    { r = 'r'; }
            if segment.write   { w = 'w'; }
            if segment.execute { x = 'x'; }

            std::println!("{:016x} - {:016x} {}{}{}",
                          segment.virt_addr, segment.virt_size, r, w, x);
        });

        elf.sections(|section| {
            std::println!("{:?}", section.name);
        });

        panic!("Done!");
    }
}
