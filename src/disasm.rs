/*
 * Copyright 2018-2020 TON DEV SOLUTIONS LTD.
 *
 * Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
 * this file except in compliance with the License.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific TON DEV software governing permissions and
 * limitations under the License.
 */

use clap::{App, ArgMatches, SubCommand, Arg, AppSettings};
use ton_types::cells_serialization::deserialize_cells_tree;
use ton_types::{Cell, SliceData, HashmapE};
use std::io::Cursor;
use std::ops::Range;

pub fn create_disasm_command<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("disasm")
        .about("Decode commands.")
        .setting(AppSettings::AllowLeadingHyphen)  
        .setting(AppSettings::TrailingVarArg)
        .setting(AppSettings::DontCollapseArgsInUsage)
        .subcommand(SubCommand::with_name("dump")
            .arg(Arg::with_name("TVC")
                    .required(true)
                    .help("Path to tvc file")))
        .subcommand(SubCommand::with_name("binary0")
            .arg(Arg::with_name("TVC")
                    .required(true)
                    .help("Path to tvc file")))
}

pub fn disasm_command(m: &ArgMatches) -> Result<(), String> {
    if let Some(m) = m.subcommand_matches("dump") {
        return disasm_dump_command(m);
    } else if let Some(m) = m.subcommand_matches("binary0") {
        return disasm_binary0_command(m);
    }
    Err("unknown command".to_owned())
}

fn disasm_dump_command(m: &ArgMatches) -> Result<(), String> {
    let filename = m.value_of("TVC");
    let tvc = filename.map(|f| std::fs::read(f))
        .transpose()
        .map_err(|e| format!(" failed to read tvc file: {}", e))?
        .unwrap();
    let mut csor = Cursor::new(tvc);
    let mut roots = deserialize_cells_tree(&mut csor).unwrap();
    let code = roots.remove(0).reference(0).unwrap();
    print_tree_of_cells(&code);
    Ok(())
}

fn disasm_binary0_command(m: &ArgMatches) -> Result<(), String> {
    let filename = m.value_of("TVC");
    let tvc = filename.map(|f| std::fs::read(f))
        .transpose()
        .map_err(|e| format!(" failed to read tvc file: {}", e))?
        .unwrap();
    let mut csor = Cursor::new(tvc);
    let mut roots = deserialize_cells_tree(&mut csor).unwrap();
    let code = roots.remove(0).reference(0).unwrap();

    let mut data = SliceData::from(code);
    let asm = disassemble(&mut data, false);
    print!("{}", asm);

    let dict = HashmapE::with_hashmap(32, data.reference(0).ok());
    for entry in dict.into_iter() {
        let (key, mut method) = entry.unwrap();
        let mut key_slice = SliceData::from(key.into_cell().unwrap());
        let id = key_slice.get_next_u32().unwrap();
        if id != 0xffffffff {
            continue;
        }
        println!("=============================== method {:x}:", id);
        //println!("{}", method);
        //println!("{}", method.to_hex_string());
        print!("{}", disassemble(&mut method, true));
    }

    println!("=============================== c3 continuation:");
    let c3 = data.reference(1).unwrap();
    let mut c3_slice = SliceData::from(c3);
    print!("{}", disassemble(&mut c3_slice, false));

    let dict2 = HashmapE::with_hashmap(32, c3_slice.reference(0).ok());
    for entry in dict2.into_iter() {
        let (key, mut func) = entry.unwrap();
        let mut key_slice = SliceData::from(key.into_cell().unwrap());
        let id = key_slice.get_next_u32().unwrap();
        println!("=============================== function {}:", id);
        print!("{}", disassemble(&mut func, true));
    }

    Ok(())
}

fn print_tree_of_cells(toc: &Cell) {
    fn print_tree_of_cells(cell: &Cell, prefix: String, last: bool) {
        let indent = if last { "└ " } else { "├ " };
        let mut hex = cell.to_hex_string(true);
        if hex.len() > 0 {
            let mut first = true;
            while hex.len() > 64 {
                let tail = hex.split_off(64);
                println!("{}{}{}…", prefix, if first { indent } else { if !last { "│ " } else { "  " } }, hex);
                hex = tail;
                first = false;
            }
            println!("{}{}{}", prefix, if first { indent } else { if !last { "│ " } else { "  " } }, hex);
        } else {
            println!("{}{}{}", prefix, indent, "1_");
        }

        let prefix_child = if last { "  " } else { "│ " };
        let prefix = prefix + prefix_child;
        if cell.references_count() > 0 {
            let last_child = cell.references_count() - 1;
            for i in 0..cell.references_count() {
                let child = cell.reference(i).unwrap();
                print_tree_of_cells(&child, prefix.to_string(), i == last_child);
            }
        }
    }
    print_tree_of_cells(&toc, "".to_string(), true);
}

fn indent(text: String) -> String {
    let mut indented = "".to_string();
    for line in text.split("\n") {
        if line.is_empty() { break; }
        indented += "  ";
        indented += line;
        indented += "\n";
    }
    indented
}

fn disassemble(slice: &mut SliceData, cont: bool) -> String {
    let mut disasm = String::new();
    let handlers = Handlers::new_code_page_0();
    let mut stop = false;
    if slice.is_empty() && cont {
        if slice.remaining_references() == 1 {
            *slice = SliceData::from(slice.reference(0).unwrap())
        } else if slice.remaining_references() > 1 {
            panic!();
        }
    }
    while !slice.is_empty() {
        //println!("before {}", slice);
        while let Ok(handler) = handlers.get_handler(&mut slice.clone()) {
            if let Some(insn) = handler(slice) {
                disasm += &insn;
                disasm += "\n";
            } else {
                disasm += "> ";
                disasm += &slice.to_hex_string();
                disasm += "\n";
                stop = true;
                break;
            }
        }
        if stop || !cont {
            break;
        }
        //println!("after {}", slice);
        assert!(slice.remaining_references() < 2);
        if slice.remaining_references() == 1 {
            *slice = SliceData::from(slice.reference(0).unwrap());
            //println!("next {}", slice);
        }
    }
    disasm
}

trait OperationBehavior {
    fn suffix() -> String;
}
pub struct Signaling {}
pub struct Quiet {}
impl OperationBehavior for Signaling {
    fn suffix() -> String { "".to_string() }
}
impl OperationBehavior for Quiet {
    fn suffix() -> String { "Q".to_string() }
}

type ExecuteHandler = fn(&mut SliceData) -> Option<String>;

#[derive(Clone, Copy)]
enum Handler {
    Direct(ExecuteHandler),
    Subset(usize),
}

pub struct Handlers {
    directs: [Handler; 256],
    subsets: Vec<Handlers>,
}

impl Handlers {
    fn new() -> Handlers {
        Handlers {
            directs: [Handler::Direct(disasm_unknown); 256],
            subsets: Vec::new(),
        }
    }

    pub(super) fn new_code_page_0() -> Handlers {
        let mut handlers = Handlers::new();
        handlers
            .add_code_page_0_part_stack()
            .add_code_page_0_tuple()
            .add_code_page_0_part_constant()
            .add_code_page_0_arithmetic()
            .add_code_page_0_comparsion()
            .add_code_page_0_cell()
            .add_code_page_0_control_flow()
            .add_code_page_0_exceptions()
            .add_code_page_0_dictionaries()
            .add_code_page_0_gas_rand_config()
            .add_code_page_0_blockchain()
            .add_code_page_0_crypto()
            .add_code_page_0_debug()
            .add_subset(0xFF, Handlers::new()
                .set_range(0x00..0xF0, disasm_setcp)
                .set(0xF0, disasm_setcpx)
                .set_range(0xF1..0xFF, disasm_setcp)
                .set(0xFF, disasm_setcp)
            );
        handlers
    }

    fn add_code_page_0_part_stack(&mut self) -> &mut Handlers {
        self
            .set(0x00, disasm_nop)
            .set_range(0x01..0x10, disasm_xchg_simple)
            .set(0x10, disasm_xchg_std)
            .set(0x11, disasm_xchg_long)
            .set_range(0x12..0x20, disasm_xchg_simple)
            .set_range(0x20..0x30, disasm_push_simple)
            .set_range(0x30..0x40, disasm_pop_simple)
            .set_range(0x40..0x50, disasm_xchg3)
            .set(0x50, disasm_xchg2)
            .set(0x51, disasm_xcpu)
            .set(0x52, disasm_puxc)
            .set(0x53, disasm_push2)
            .add_subset(0x54, Handlers::new() 
                .set_range(0x00..0x10, disasm_xchg3)
                .set_range(0x10..0x20, disasm_xc2pu)
                .set_range(0x20..0x30, disasm_xcpuxc)
                .set_range(0x30..0x40, disasm_xcpu2)
                .set_range(0x40..0x50, disasm_puxc2)
                .set_range(0x50..0x60, disasm_puxcpu)
                .set_range(0x60..0x70, disasm_pu2xc)
                .set_range(0x70..0x80, disasm_push3)
            )
            .set(0x55, disasm_blkswap)
            .set(0x56, disasm_push)
            .set(0x57, disasm_pop)
            .set(0x58, disasm_rot)
            .set(0x59, disasm_rotrev)
            .set(0x5A, disasm_swap2)
            .set(0x5B, disasm_drop2)
            .set(0x5C, disasm_dup2)
            .set(0x5D, disasm_over2)
            .set(0x5E, disasm_reverse)
            .add_subset(0x5F, Handlers::new()
                .set_range(0x00..0x10, disasm_blkdrop)
                .set_range(0x10..0xFF, disasm_blkpush)
                .set(0xFF, disasm_blkpush)
            )
            .set(0x60, disasm_pick)
            .set(0x61, disasm_roll)
            .set(0x62, disasm_rollrev)
            .set(0x63, disasm_blkswx)
            .set(0x64, disasm_revx)
            .set(0x65, disasm_dropx)
            .set(0x66, disasm_tuck)
            .set(0x67, disasm_xchgx)
            .set(0x68, disasm_depth)
            .set(0x69, disasm_chkdepth)
            .set(0x6A, disasm_onlytopx)
            .set(0x6B, disasm_onlyx)
            .add_subset(0x6C, Handlers::new()
                .set_range(0x10..0xFF, disasm_blkdrop2)
                .set(0xFF, disasm_blkdrop2)
            )
    }

    fn add_code_page_0_tuple(&mut self) -> &mut Handlers {
        self
            .set(0x6D, disasm_null)
            .set(0x6E, disasm_isnull)
            .add_subset(0x6F, Handlers::new()
                .set_range(0x00..0x10, disasm_tuple_create)
                .set_range(0x10..0x20, disasm_tuple_index)
                .set_range(0x20..0x30, disasm_tuple_un)
                .set_range(0x30..0x40, disasm_tuple_unpackfirst)
                .set_range(0x40..0x50, disasm_tuple_explode)
                .set_range(0x50..0x60, disasm_tuple_setindex)
                .set_range(0x60..0x70, disasm_tuple_index_quiet)
                .set_range(0x70..0x80, disasm_tuple_setindex_quiet)
                .set(0x80, disasm_tuple_createvar)
                .set(0x81, disasm_tuple_indexvar)
                .set(0x82, disasm_tuple_untuplevar)
                .set(0x83, disasm_tuple_unpackfirstvar)
                .set(0x84, disasm_tuple_explodevar)
                .set(0x85, disasm_tuple_setindexvar)
                .set(0x86, disasm_tuple_indexvar_quiet)
                .set(0x87, disasm_tuple_setindexvar_quiet)
                .set(0x88, disasm_tuple_len)
                .set(0x89, disasm_tuple_len_quiet)
                .set(0x8A, disasm_istuple)
                .set(0x8B, disasm_tuple_last)
                .set(0x8C, disasm_tuple_push)
                .set(0x8D, disasm_tuple_pop)
                .set(0xA0, disasm_nullswapif)
                .set(0xA1, disasm_nullswapifnot)
                .set(0xA2, disasm_nullrotrif)
                .set(0xA3, disasm_nullrotrifnot)
                .set(0xA4, disasm_nullswapif2)
                .set(0xA5, disasm_nullswapifnot2)
                .set(0xA6, disasm_nullrotrif2)
                .set(0xA7, disasm_nullrotrifnot2)
                .set_range(0xB0..0xC0, disasm_tuple_index2)
                .set_range(0xC0..0xFF, disasm_tuple_index3)
                .set(0xFF, disasm_tuple_index3)
            )
    }

    fn add_code_page_0_part_constant(&mut self) -> &mut Handlers {
        self
            .set_range(0x70..0x82, disasm_pushint)
            .set(0x82, disasm_pushint_big)
            .add_subset(0x83, Handlers::new()
                .set_range(0x00..0xFF, disasm_pushpow2)
                .set(0xFF, disasm_pushnan)
            )
            .set(0x84, disasm_pushpow2dec)
            .set(0x85, disasm_pushnegpow2)
            .set(0x88, disasm_pushref)
            .set(0x89, disasm_pushrefslice)
            .set(0x8A, disasm_pushrefcont)
            .set(0x8B, disasm_pushslice_short)
            .set(0x8C, disasm_pushslice_mid)
            .set(0x8D, disasm_pushslice_long)
            .set_range(0x8E..0x90, disasm_pushcont_long)
            .set_range(0x90..0xA0, disasm_pushcont_short)
    }

    fn add_code_page_0_arithmetic(&mut self) -> &mut Handlers {
        self
            .set(0xA0, disasm_add::<Signaling>)
            .set(0xA1, disasm_sub::<Signaling>)
            .set(0xA2, disasm_subr::<Signaling>)
            .set(0xA3, disasm_negate::<Signaling>)
            .set(0xA4, disasm_inc::<Signaling>)
            .set(0xA5, disasm_dec::<Signaling>)
            .set(0xA6, disasm_addconst::<Signaling>)
            .set(0xA7, disasm_mulconst::<Signaling>)
            .set(0xA8, disasm_mul::<Signaling>)
            .set(0xA9, disasm_divmod::<Signaling>)
            .set(0xAA, disasm_lshift::<Signaling>)
            .set(0xAB, disasm_rshift::<Signaling>)
            .set(0xAC, disasm_lshift::<Signaling>)
            .set(0xAD, disasm_rshift::<Signaling>)
            .set(0xAE, disasm_pow2::<Signaling>)
            .set(0xB0, disasm_and::<Signaling>)
            .set(0xB1, disasm_or::<Signaling>)
            .set(0xB2, disasm_xor::<Signaling>)
            .set(0xB3, disasm_not::<Signaling>)
            .set(0xB4, disasm_fits::<Signaling>)
            .set(0xB5, disasm_ufits::<Signaling>)
            .add_subset(0xB6, Handlers::new()
                .set(0x00, disasm_fitsx::<Signaling>)
                .set(0x01, disasm_ufitsx::<Signaling>)
                .set(0x02, disasm_bitsize::<Signaling>)
                .set(0x03, disasm_ubitsize::<Signaling>)
                .set(0x08, disasm_min::<Signaling>)
                .set(0x09, disasm_max::<Signaling>)
                .set(0x0A, disasm_minmax::<Signaling>)
                .set(0x0B, disasm_abs::<Signaling>)
            )
            .add_subset(0xB7, Handlers::new()
                .set(0xA0, disasm_add::<Quiet>)
                .set(0xA1, disasm_sub::<Quiet>)
                .set(0xA2, disasm_subr::<Quiet>)
                .set(0xA3, disasm_negate::<Quiet>)
                .set(0xA4, disasm_inc::<Quiet>)
                .set(0xA5, disasm_dec::<Quiet>)
                .set(0xA6, disasm_addconst::<Quiet>)
                .set(0xA7, disasm_mulconst::<Quiet>)
                .set(0xA8, disasm_mul::<Quiet>)
                .set(0xA9, disasm_divmod::<Quiet>)
                .set(0xAA, disasm_lshift::<Quiet>)
                .set(0xAB, disasm_rshift::<Quiet>)
                .set(0xAC, disasm_lshift::<Quiet>)
                .set(0xAD, disasm_rshift::<Quiet>)
                .set(0xAE, disasm_pow2::<Quiet>)
                .set(0xB0, disasm_and::<Quiet>)
                .set(0xB1, disasm_or::<Quiet>)
                .set(0xB2, disasm_xor::<Quiet>)
                .set(0xB3, disasm_not::<Quiet>)
                .set(0xB4, disasm_fits::<Quiet>)
                .set(0xB5, disasm_ufits::<Quiet>)
                .add_subset(0xB6, Handlers::new()
                    .set(0x00, disasm_fitsx::<Quiet>)
                    .set(0x01, disasm_ufitsx::<Quiet>)
                    .set(0x02, disasm_bitsize::<Quiet>)
                    .set(0x03, disasm_ubitsize::<Quiet>)
                    .set(0x08, disasm_min::<Quiet>)
                    .set(0x09, disasm_max::<Quiet>)
                    .set(0x0A, disasm_minmax::<Quiet>)
                    .set(0x0B, disasm_abs::<Quiet>)
                )
                .set(0xB8, disasm_sgn::<Quiet>)
                .set(0xB9, disasm_less::<Quiet>)
                .set(0xBA, disasm_equal::<Quiet>)
                .set(0xBB, disasm_leq::<Quiet>)
                .set(0xBC, disasm_greater::<Quiet>)
                .set(0xBD, disasm_neq::<Quiet>)
                .set(0xBE, disasm_geq::<Quiet>)
                .set(0xBF, disasm_cmp::<Quiet>)
                .set(0xC0, disasm_eqint::<Quiet>)
                .set(0xC1, disasm_lessint::<Quiet>)
                .set(0xC2, disasm_gtint::<Quiet>)
                .set(0xC3, disasm_neqint::<Quiet>)
            )
    }

    fn add_code_page_0_comparsion(&mut self) -> &mut Handlers {
        self
            .set(0xB8, disasm_sgn::<Signaling>)
            .set(0xB9, disasm_less::<Signaling>)
            .set(0xBA, disasm_equal::<Signaling>)
            .set(0xBB, disasm_leq::<Signaling>)
            .set(0xBC, disasm_greater::<Signaling>)
            .set(0xBD, disasm_neq::<Signaling>)
            .set(0xBE, disasm_geq::<Signaling>)
            .set(0xBF, disasm_cmp::<Signaling>)
            .set(0xC0, disasm_eqint::<Signaling>)
            .set(0xC1, disasm_lessint::<Signaling>)
            .set(0xC2, disasm_gtint::<Signaling>)
            .set(0xC3, disasm_neqint::<Signaling>)
            .set(0xC4, disasm_isnan)
            .set(0xC5, disasm_chknan)
            .add_subset(0xC7, Handlers::new()
                .set(0x00, disasm_sempty)
                .set(0x01, disasm_sdempty)
                .set(0x02, disasm_srempty)
                .set(0x03, disasm_sdfirst)
                .set(0x04, disasm_sdlexcmp)
                .set(0x05, disasm_sdeq)
                .set(0x08, disasm_sdpfx)
                .set(0x09, disasm_sdpfxrev)
                .set(0x0A, disasm_sdppfx)
                .set(0x0B, disasm_sdppfxrev)
                .set(0x0C, disasm_sdsfx)
                .set(0x0D, disasm_sdsfxrev)
                .set(0x0E, disasm_sdpsfx)
                .set(0x0F, disasm_sdpsfxrev)
                .set(0x10, disasm_sdcntlead0)
                .set(0x11, disasm_sdcntlead1)
                .set(0x12, disasm_sdcnttrail0)
                .set(0x13, disasm_sdcnttrail1)
            )
    }

    fn add_code_page_0_cell(&mut self) -> &mut Handlers {
        self
            .set(0xC8, disasm_newc)
            .set(0xC9, disasm_endc)
            .set(0xCA, disasm_sti)
            .set(0xCB, disasm_stu)
            .set(0xCC, disasm_stref)
            .set(0xCD, disasm_endcst)
            .set(0xCE, disasm_stslice)
            .add_subset(0xCF, Handlers::new()
                .set(0x00, disasm_stix)
                .set(0x01, disasm_stux)
                .set(0x02, disasm_stixr)
                .set(0x03, disasm_stuxr)
                .set(0x04, disasm_stixq)
                .set(0x05, disasm_stuxq)
                .set(0x06, disasm_stixrq)
                .set(0x07, disasm_stuxrq)
                .set(0x08, disasm_sti)
                .set(0x09, disasm_stu)
                .set(0x0A, disasm_stir)
                .set(0x0B, disasm_stur)
                .set(0x0C, disasm_stiq)
                .set(0x0D, disasm_stuq)
                .set(0x0E, disasm_stirq)
                .set(0x0F, disasm_sturq)
                .set(0x10, disasm_stref)
                .set(0x11, disasm_stbref)
                .set(0x12, disasm_stslice)
                .set(0x13, disasm_stb)
                .set(0x14, disasm_strefr)
                .set(0x15, disasm_endcst)
                .set(0x16, disasm_stslicer)
                .set(0x17, disasm_stbr)
                .set(0x18, disasm_strefq)
                .set(0x19, disasm_stbrefq)
                .set(0x1A, disasm_stsliceq)
                .set(0x1B, disasm_stbq)
                .set(0x1C, disasm_strefrq)
                .set(0x1D, disasm_stbrefrq)
                .set(0x1E, disasm_stslicerq)
                .set(0x1F, disasm_stbrq)
                .set(0x20, disasm_strefconst)
                .set(0x21, disasm_stref2const)
                .set(0x23, disasm_endxc)
                .set(0x28, disasm_stile4)
                .set(0x29, disasm_stule4)
                .set(0x2A, disasm_stile8)
                .set(0x2B, disasm_stule8)
                .set(0x30, disasm_bdepth)
                .set(0x31, disasm_bbits)
                .set(0x32, disasm_brefs)
                .set(0x33, disasm_bbitrefs)
                .set(0x35, disasm_brembits)
                .set(0x36, disasm_bremrefs)
                .set(0x37, disasm_brembitrefs)
                .set(0x38, disasm_bchkbits_short)
                .set(0x39, disasm_bchkbits_long)
                .set(0x3A, disasm_bchkrefs)
                .set(0x3B, disasm_bchkbitrefs)
                .set(0x3C, disasm_bchkbitsq_short)
                .set(0x3D, disasm_bchkbitsq_long)
                .set(0x3E, disasm_bchkrefsq)
                .set(0x3F, disasm_bchkbitrefsq)
                .set(0x40, disasm_stzeroes)
                .set(0x41, disasm_stones)
                .set(0x42, disasm_stsame)
                .set_range(0x80..0xFF, disasm_stsliceconst)
                .set(0xFF, disasm_stsliceconst)
            )
            .set(0xD0, disasm_ctos)
            .set(0xD1, disasm_ends)
            .set(0xD2, disasm_ldi)
            .set(0xD3, disasm_ldu)
            .set(0xD4, disasm_ldref)
            .set(0xD5, disasm_ldrefrtos)
            .set(0xD6, disasm_ldslice)
            .add_subset(0xD7, Handlers::new()
                .set(0x00, disasm_ldix)
                .set(0x01, disasm_ldux)
                .set(0x02, disasm_pldix)
                .set(0x03, disasm_pldux)
                .set(0x04, disasm_ldixq)
                .set(0x05, disasm_lduxq)
                .set(0x06, disasm_pldixq)
                .set(0x07, disasm_plduxq)
                .set(0x08, disasm_ldi)
                .set(0x09, disasm_ldu)
                .set(0x0A, disasm_pldi)
                .set(0x0B, disasm_pldu)
                .set(0x0C, disasm_ldiq)
                .set(0x0D, disasm_lduq)
                .set(0x0E, disasm_pldiq)
                .set(0x0F, disasm_plduq)
                .set_range(0x10..0x18, disasm_plduz)
                .set(0x18, disasm_ldslicex)
                .set(0x19, disasm_pldslicex)
                .set(0x1A, disasm_ldslicexq)
                .set(0x1B, disasm_pldslicexq)
                .set(0x1C, disasm_ldslice)
                .set(0x1D, disasm_pldslice)
                .set(0x1E, disasm_ldsliceq)
                .set(0x1F, disasm_pldsliceq)
                .set(0x20, disasm_pldslicex)
                .set(0x21, disasm_sdskipfirst)
                .set(0x22, disasm_sdcutlast)
                .set(0x23, disasm_sdskiplast)
                .set(0x24, disasm_sdsubstr)
                .set(0x26, disasm_sdbeginsx)
                .set(0x27, disasm_sdbeginsxq)
                .set_range(0x28..0x2C, disasm_sdbegins)
                .set_range(0x2C..0x30, disasm_sdbeginsq)
                .set(0x30, disasm_scutfirst)
                .set(0x31, disasm_sskipfirst)
                .set(0x32, disasm_scutlast)
                .set(0x33, disasm_sskiplast)
                .set(0x34, disasm_subslice)
                .set(0x36, disasm_split)
                .set(0x37, disasm_splitq)
                .set(0x39, disasm_xctos)
                .set(0x3A, disasm_xload)
                .set(0x3B, disasm_xloadq)
                .set(0x41, disasm_schkbits)
                .set(0x42, disasm_schkrefs)
                .set(0x43, disasm_schkbitrefs)
                .set(0x45, disasm_schkbitsq)
                .set(0x46, disasm_schkrefsq)
                .set(0x47, disasm_schkbitrefsq)
                .set(0x48, disasm_pldrefvar)
                .set(0x49, disasm_sbits)
                .set(0x4A, disasm_srefs)
                .set(0x4B, disasm_sbitrefs)
                .set(0x4C, disasm_pldref)
                .set_range(0x4D..0x50, disasm_pldrefidx)
                .set(0x50, disasm_ldile4) 
                .set(0x51, disasm_ldule4) 
                .set(0x52, disasm_ldile8) 
                .set(0x53, disasm_ldule8) 
                .set(0x54, disasm_pldile4)
                .set(0x55, disasm_pldule4)
                .set(0x56, disasm_pldile8)
                .set(0x57, disasm_pldule8)
                .set(0x58, disasm_ldile4q) 
                .set(0x59, disasm_ldule4q) 
                .set(0x5A, disasm_ldile8q) 
                .set(0x5B, disasm_ldule8q) 
                .set(0x5C, disasm_pldile4q)
                .set(0x5D, disasm_pldule4q)
                .set(0x5E, disasm_pldile8q)
                .set(0x5F, disasm_pldule8q)
                .set(0x60, disasm_ldzeroes)
                .set(0x61, disasm_ldones)
                .set(0x62, disasm_ldsame)
                .set(0x64, disasm_sdepth)
                .set(0x65, disasm_cdepth)
            )
    }

    fn add_code_page_0_control_flow(&mut self) -> &mut Handlers {
        self
            .set(0xD8, disasm_callx)
            .set(0xD9, disasm_jmpx)
            .set(0xDA, disasm_callxargs)
            .add_subset(0xDB, Handlers::new()
                .set_range(0x00..0x10, disasm_callxargs)
                .set_range(0x10..0x20, disasm_jmpxargs)
                .set_range(0x20..0x30, disasm_retargs)
                .set(0x30, disasm_ret)
                .set(0x31, disasm_retalt)
                .set(0x32, disasm_retbool)
                .set(0x34, disasm_callcc)
                .set(0x35, disasm_jmpxdata)
                .set(0x36, disasm_callccargs)
                .set(0x38, disasm_callxva)
                .set(0x39, disasm_retva)
                .set(0x3A, disasm_jmpxva)
                .set(0x3B, disasm_callccva)
                .set(0x3C, disasm_callref)
                .set(0x3D, disasm_jmpref)
                .set(0x3E, disasm_jmprefdata)
                .set(0x3F, disasm_retdata)
            )
            .set(0xDE, disasm_if)
            .set(0xDC, disasm_ifret)
            .set(0xDD, disasm_ifnotret)
            .set(0xDF, disasm_ifnot)
            .set(0xE0, disasm_ifjmp)
            .set(0xE1, disasm_ifnotjmp)
            .set(0xE2, disasm_ifelse)
            .add_subset(0xE3, Handlers::new()
                .set(0x00, disasm_ifref)
                .set(0x01, disasm_ifnotref)
                .set(0x02, disasm_ifjmpref)
                .set(0x03, disasm_ifnotjmpref)
                .set(0x04, disasm_condsel)
                .set(0x05, disasm_condselchk)
                .set(0x08, disasm_ifretalt)
                .set(0x09, disasm_ifnotretalt)
                .set(0x0D, disasm_ifrefelse)
                .set(0x0E, disasm_ifelseref)
                .set(0x0F, disasm_ifrefelseref)
                .set(0x14, disasm_repeat_break)
                .set(0x15, disasm_repeatend_break)
                .set(0x16, disasm_until_break)
                .set(0x17, disasm_untilend_break)
                .set(0x18, disasm_while_break)
                .set(0x19, disasm_whileend_break)
                .set(0x1A, disasm_again_break)
                .set(0x1B, disasm_againend_break)
                .set_range(0x80..0xA0, disasm_ifbitjmp)
                .set_range(0xA0..0xC0, disasm_ifnbitjmp)
                .set_range(0xC0..0xE0, disasm_ifbitjmpref)
                .set_range(0xE0..0xFF, disasm_ifnbitjmpref)
                .set(0xFF, disasm_ifnbitjmpref)
             )
            .set(0xE4, disasm_repeat)
            .set(0xE5, disasm_repeatend)
            .set(0xE6, disasm_until)
            .set(0xE7, disasm_untilend)
            .set(0xE8, disasm_while)
            .set(0xE9, disasm_whileend)
            .set(0xEA, disasm_again)
            .set(0xEB, disasm_againend)
            .set(0xEC, disasm_setcontargs)
            .add_subset(0xED, Handlers::new()
                .set_range(0x00..0x10, disasm_returnargs)
                .set(0x10, disasm_returnva)
                .set(0x11, disasm_setcontva)
                .set(0x12, disasm_setnumvarargs)
                .set(0x1E, disasm_bless)
                .set(0x1F, disasm_blessva)
                .set_range(0x40..0x50, disasm_pushctr)
                .set_range(0x50..0x60, disasm_popctr)
                .set_range(0x60..0x70, disasm_setcontctr)
                .set_range(0x70..0x80, disasm_setretctr)
                .set_range(0x80..0x90, disasm_setaltctr)
                .set_range(0x90..0xA0, disasm_popsave)
                .set_range(0xA0..0xB0, disasm_save)
                .set_range(0xB0..0xC0, disasm_savealt)
                .set_range(0xC0..0xD0, disasm_saveboth)
                .set(0xE0, disasm_pushctrx)
                .set(0xE1, disasm_popctrx)
                .set(0xE2, disasm_setcontctrx)
                .set(0xF0, disasm_compos)
                .set(0xF1, disasm_composalt)
                .set(0xF2, disasm_composboth)
                .set(0xF3, disasm_atexit)
                .set(0xF4, disasm_atexitalt)
                .set(0xF5, disasm_setexitalt)
                .set(0xF6, disasm_thenret)
                .set(0xF7, disasm_thenretalt)
                .set(0xF8, disasm_invert)
                .set(0xF9, disasm_booleval)
                .set(0xFA, disasm_samealt)
                .set(0xFB, disasm_samealt_save)
            )
            .set(0xEE, disasm_blessargs)
            .set(0xF0, disasm_call_short)
            .add_subset(0xF1, Handlers::new()
                .set_range(0x00..0x40, disasm_call_long)
                .set_range(0x40..0x80, disasm_jmp)
                .set_range(0x80..0xC0, disasm_prepare)
            )
    }

    fn add_code_page_0_exceptions(&mut self) -> &mut Handlers {
        self
            .add_subset(0xF2, Handlers::new()
                .set_range(0x00..0x40, disasm_throw_short)
                .set_range(0x40..0x80, disasm_throwif_short)
                .set_range(0x80..0xC0, disasm_throwifnot_short)
                .set_range(0xC0..0xC8, disasm_throw_long)
                .set_range(0xC8..0xD0, disasm_throwarg)
                .set_range(0xD0..0xD8, disasm_throwif_long)
                .set_range(0xD8..0xE0, disasm_throwargif)
                .set_range(0xE0..0xE8, disasm_throwifnot_long)
                .set_range(0xE8..0xF0, disasm_throwargifnot)
                .set(0xF0, disasm_throwany)
                .set(0xF1, disasm_throwargany)
                .set(0xF2, disasm_throwanyif)
                .set(0xF3, disasm_throwarganyif)
                .set(0xF4, disasm_throwanyifnot)
                .set(0xF5, disasm_throwarganyifnot)
                .set(0xFF, disasm_try)
            )
            .set(0xF3, disasm_tryargs)
    }

    fn add_code_page_0_blockchain(&mut self) -> &mut Handlers {
        self
            .add_subset(0xFA, Handlers::new()
                .set(0x00, disasm_ldgrams)
                .set(0x01, disasm_ldvarint16)
                .set(0x02, disasm_stgrams)
                .set(0x03, disasm_stvarint16)
                .set(0x04, disasm_ldvaruint32)
                .set(0x05, disasm_ldvarint32)
                .set(0x06, disasm_stvaruint32)
                .set(0x07, disasm_stvarint32)
                .set(0x40, disasm_ldmsgaddr::<Signaling>)
                .set(0x41, disasm_ldmsgaddr::<Quiet>)
                .set(0x42, disasm_parsemsgaddr::<Signaling>)
                .set(0x43, disasm_parsemsgaddr::<Quiet>)
                .set(0x44, disasm_rewrite_std_addr::<Signaling>)
                .set(0x45, disasm_rewrite_std_addr::<Quiet>)
                .set(0x46, disasm_rewrite_var_addr::<Signaling>)
                .set(0x47, disasm_rewrite_var_addr::<Quiet>)
            )
            .add_subset(0xFB, Handlers::new()
                .set(0x00, disasm_sendrawmsg)
                .set(0x02, disasm_rawreserve)
                .set(0x03, disasm_rawreservex)
                .set(0x04, disasm_setcode)
                .set(0x06, disasm_setlibcode)
                .set(0x07, disasm_changelib)
            )
    }

    fn add_code_page_0_dictionaries(&mut self) -> &mut Handlers {
        self
            .add_subset(0xF4, Handlers::new()
                .set(0x00, disasm_stdict)
                .set(0x01, disasm_skipdict)
                .set(0x02, disasm_lddicts)
                .set(0x03, disasm_plddicts)
                .set(0x04, disasm_lddict)
                .set(0x05, disasm_plddict)
                .set(0x06, disasm_lddictq)
                .set(0x07, disasm_plddictq)
                .set(0x0A, disasm_dictget)
                .set(0x0B, disasm_dictgetref)
                .set(0x0C, disasm_dictiget)
                .set(0x0D, disasm_dictigetref)
                .set(0x0E, disasm_dictuget)
                .set(0x0F, disasm_dictugetref)
                .set(0x12, disasm_dictset)
                .set(0x13, disasm_dictsetref)
                .set(0x14, disasm_dictiset)
                .set(0x15, disasm_dictisetref)
                .set(0x16, disasm_dictuset)
                .set(0x17, disasm_dictusetref)
                .set(0x1A, disasm_dictsetget)
                .set(0x1B, disasm_dictsetgetref)
                .set(0x1C, disasm_dictisetget)
                .set(0x1D, disasm_dictisetgetref)
                .set(0x1E, disasm_dictusetget)
                .set(0x1F, disasm_dictusetgetref)
                .set(0x22, disasm_dictreplace)
                .set(0x23, disasm_dictreplaceref)
                .set(0x24, disasm_dictireplace)
                .set(0x25, disasm_dictireplaceref)
                .set(0x26, disasm_dictureplace)
                .set(0x27, disasm_dictureplaceref)
                .set(0x2A, disasm_dictreplaceget)
                .set(0x2B, disasm_dictreplacegetref)
                .set(0x2C, disasm_dictireplaceget)
                .set(0x2D, disasm_dictireplacegetref)
                .set(0x2E, disasm_dictureplaceget)
                .set(0x2F, disasm_dictureplacegetref)
                .set(0x32, disasm_dictadd)
                .set(0x33, disasm_dictaddref)
                .set(0x34, disasm_dictiadd)
                .set(0x35, disasm_dictiaddref)
                .set(0x36, disasm_dictuadd)
                .set(0x37, disasm_dictuaddref)
                .set(0x3A, disasm_dictaddget)
                .set(0x3B, disasm_dictaddgetref)
                .set(0x3C, disasm_dictiaddget)
                .set(0x3D, disasm_dictiaddgetref)
                .set(0x3E, disasm_dictuaddget)
                .set(0x3F, disasm_dictuaddgetref)
                .set(0x41, disasm_dictsetb)
                .set(0x42, disasm_dictisetb)
                .set(0x43, disasm_dictusetb)
                .set(0x45, disasm_dictsetgetb)
                .set(0x46, disasm_dictisetgetb)
                .set(0x47, disasm_dictusetgetb)
                .set(0x49, disasm_dictreplaceb)
                .set(0x4A, disasm_dictireplaceb)
                .set(0x4B, disasm_dictureplaceb)
                .set(0x4D, disasm_dictreplacegetb)
                .set(0x4E, disasm_dictireplacegetb)
                .set(0x4F, disasm_dictureplacegetb)
                .set(0x51, disasm_dictaddb)
                .set(0x52, disasm_dictiaddb)
                .set(0x53, disasm_dictuaddb)
                .set(0x55, disasm_dictaddgetb)
                .set(0x56, disasm_dictiaddgetb)
                .set(0x57, disasm_dictuaddgetb)
                .set(0x59, disasm_dictdel)
                .set(0x5A, disasm_dictidel)
                .set(0x5B, disasm_dictudel)
                .set(0x62, disasm_dictdelget)
                .set(0x63, disasm_dictdelgetref)
                .set(0x64, disasm_dictidelget)
                .set(0x65, disasm_dictidelgetref)
                .set(0x66, disasm_dictudelget)
                .set(0x67, disasm_dictudelgetref)
                .set(0x69, disasm_dictgetoptref)
                .set(0x6A, disasm_dictigetoptref)
                .set(0x6B, disasm_dictugetoptref)
                .set(0x6D, disasm_dictsetgetoptref)
                .set(0x6E, disasm_dictisetgetoptref)
                .set(0x6F, disasm_dictusetgetoptref)
                .set(0x70, disasm_pfxdictset)
                .set(0x71, disasm_pfxdictreplace)
                .set(0x72, disasm_pfxdictadd)
                .set(0x73, disasm_pfxdictdel)
                .set(0x74, disasm_dictgetnext)
                .set(0x75, disasm_dictgetnexteq)
                .set(0x76, disasm_dictgetprev)
                .set(0x77, disasm_dictgetpreveq)
                .set(0x78, disasm_dictigetnext)
                .set(0x79, disasm_dictigetnexteq)
                .set(0x7A, disasm_dictigetprev)
                .set(0x7B, disasm_dictigetpreveq)
                .set(0x7C, disasm_dictugetnext)
                .set(0x7D, disasm_dictugetnexteq)
                .set(0x7E, disasm_dictugetprev)
                .set(0x7F, disasm_dictugetpreveq)
                .set(0x82, disasm_dictmin)
                .set(0x83, disasm_dictminref)
                .set(0x84, disasm_dictimin)
                .set(0x85, disasm_dictiminref)
                .set(0x86, disasm_dictumin)
                .set(0x87, disasm_dictuminref)
                .set(0x8A, disasm_dictmax)
                .set(0x8B, disasm_dictmaxref)
                .set(0x8C, disasm_dictimax)
                .set(0x8D, disasm_dictimaxref)
                .set(0x8E, disasm_dictumax)
                .set(0x8F, disasm_dictumaxref)
                .set(0x92, disasm_dictremmin)
                .set(0x93, disasm_dictremminref)
                .set(0x94, disasm_dictiremmin)
                .set(0x95, disasm_dictiremminref)
                .set(0x96, disasm_dicturemmin)
                .set(0x97, disasm_dicturemminref)
                .set(0x9A, disasm_dictremmax)
                .set(0x9B, disasm_dictremmaxref)
                .set(0x9C, disasm_dictiremmax)
                .set(0x9D, disasm_dictiremmaxref)
                .set(0x9E, disasm_dicturemmax)
                .set(0x9F, disasm_dicturemmaxref)
                .set(0xA0, disasm_dictigetjmp)
                .set(0xA1, disasm_dictugetjmp)
                .set(0xA2, disasm_dictigetexec)
                .set(0xA3, disasm_dictugetexec)
                .set_range(0xA4..0xA8, disasm_dictpushconst)
                .set(0xA8, disasm_pfxdictgetq)
                .set(0xA9, disasm_pfxdictget)
                .set(0xAA, disasm_pfxdictgetjmp)
                .set(0xAB, disasm_pfxdictgetexec)
                .set_range(0xAC..0xAF, disasm_pfxdictswitch)
                .set(0xAF, disasm_pfxdictswitch)
                .set(0xB1, disasm_subdictget)
                .set(0xB2, disasm_subdictiget)
                .set(0xB3, disasm_subdictuget)
                .set(0xB5, disasm_subdictrpget)
                .set(0xB6, disasm_subdictirpget)
                .set(0xB7, disasm_subdicturpget)
                .set(0xBC, disasm_dictigetjmpz)
                .set(0xBD, disasm_dictugetjmpz)
                .set(0xBE, disasm_dictigetexecz)
                .set(0xBF, disasm_dictugetexecz)
            )
    }

    fn add_code_page_0_gas_rand_config(&mut self) -> &mut Handlers {
        self
            .add_subset(0xF8, Handlers::new()
                .set(0x00, disasm_accept)
                .set(0x01, disasm_setgaslimit)
                .set(0x02, disasm_buygas)
                .set(0x04, disasm_gramtogas)
                .set(0x05, disasm_gastogram)
                .set(0x0F, disasm_commit)
                .set(0x10, disasm_randu256)
                .set(0x11, disasm_rand)
                .set(0x14, disasm_setrand)
                .set(0x15, disasm_addrand)
                .set(0x20, disasm_getparam)
                .set(0x21, disasm_getparam)
                .set(0x22, disasm_getparam)
                .set(0x23, disasm_now)
                .set(0x24, disasm_blocklt)
                .set(0x25, disasm_ltime)
                .set(0x26, disasm_randseed)
                .set(0x27, disasm_balance)
                .set(0x28, disasm_my_addr)
                .set(0x29, disasm_config_root)
                .set(0x30, disasm_config_dict)
                .set(0x32, disasm_config_ref_param)
                .set(0x33, disasm_config_opt_param)
                .set(0x40, disasm_getglobvar)
                .set_range(0x41..0x5F, disasm_getglob)
                .set(0x5F, disasm_getglob)
                .set(0x60, disasm_setglobvar)
                .set_range(0x61..0x7F, disasm_setglob)
                .set(0x7F, disasm_setglob)
            )
    }

    fn add_code_page_0_crypto(&mut self) -> &mut Handlers {
        self
        .add_subset(0xF9, Handlers::new()
            .set(0x00, disasm_hashcu)
            .set(0x01, disasm_hashsu)
            .set(0x02, disasm_sha256u)
            .set(0x10, disasm_chksignu)
            .set(0x11, disasm_chksigns)
            .set(0x40, disasm_cdatasizeq)
            .set(0x41, disasm_cdatasize)
            .set(0x42, disasm_sdatasizeq)
            .set(0x43, disasm_sdatasize)
        )
    }

    fn add_code_page_0_debug(&mut self) -> &mut Handlers {
        self.add_subset(0xFE, Handlers::new()
            .set(0x00, disasm_dump_stack)
            .set_range(0x01..0x0F, disasm_dump_stack_top)
            .set(0x10, disasm_dump_hex)
            .set(0x11, disasm_print_hex)
            .set(0x12, disasm_dump_bin)
            .set(0x13, disasm_print_bin)
            .set(0x14, disasm_dump_str)
            .set(0x15, disasm_print_str)
            .set(0x1E, disasm_debug_off)
            .set(0x1F, disasm_debug_on)
            .set_range(0x20..0x2F, disasm_dump_var)
            .set_range(0x30..0x3F, disasm_print_var)
            .set_range(0xF0..0xFF, disasm_dump_string)
            .set(0xFF, disasm_dump_string)
        )
    }

    fn get_handler(&self, slice: &mut SliceData) -> ton_types::Result<ExecuteHandler> {
        let cmd = slice.get_next_byte()?;
        match self.directs[cmd as usize] {
            Handler::Direct(handler) => Ok(handler),
            Handler::Subset(i) => self.subsets[i].get_handler(slice),
        }
    }

    fn add_subset(&mut self, code: u8, subset: &mut Handlers) -> &mut Handlers {
        match self.directs[code as usize] {
            Handler::Direct(x) => if x as usize == disasm_unknown as usize {
                self.directs[code as usize] = Handler::Subset(self.subsets.len());
                self.subsets.push(std::mem::replace(subset, Handlers::new()))
            } else {
                panic!("Slot for subset {:02x} is already occupied", code)
            },
            _ => panic!("Subset {:02x} is already registered", code),
        }
        self
    }

    fn register_handler(&mut self, code: u8, handler: ExecuteHandler) {
        match self.directs[code as usize] {
            Handler::Direct(x) => if x as usize == disasm_unknown as usize {
                self.directs[code as usize] = Handler::Direct(handler)
            } else {
                panic!("Code {:02x} is already registered", code)
            },
            _ => panic!("Slot for code {:02x} is already occupied", code),
        }
    }

    fn set(&mut self, code: u8, handler: ExecuteHandler) -> &mut Handlers {
        self.register_handler(code, handler);
        self
    }

    fn set_range(&mut self, codes: Range<u8>, handler: ExecuteHandler) -> &mut Handlers {
        for code in codes {
            self.register_handler(code, handler);
        }
        self
    }
}

fn disasm_unknown(slice: &mut SliceData) -> Option<String> {
    println!("XXX: {}", slice.to_hex_string());
    None
}
fn disasm_setcp(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xff);
    match slice.get_next_byte() {
        Ok(0) => Some("SETCP0".to_string()),
        _ => None
    }
}
fn disasm_setcpx(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfff0);
    Some("SETCPX".to_string())
}
fn disasm_nop(slice: &mut SliceData) -> Option<String> {
    slice.move_by(8).unwrap();
    Some("NOP".to_string())
}
fn disasm_xchg_simple(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(4).unwrap();
    assert!(opc == 0 || opc == 1);
    let i = slice.get_next_int(4).unwrap();
    match opc {
        0 => Some(format!("XCHG s{}", i).to_string()),
        1 => Some(format!("XCHG s1, s{}", i).to_string()),
        _ => None
    }
}
fn disasm_xchg_std(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x10);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    Some(format!("XCHG s{}, s{}", i, j).to_string())
}
fn disasm_xchg_long(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x11);
    let ii = slice.get_next_int(8).unwrap();
    Some(format!("XCHG s0, s{}", ii).to_string())
}
fn disasm_push_simple(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(4).unwrap();
    assert!(opc == 0x2);
    let i = slice.get_next_int(4).unwrap();
    Some(format!("PUSH s{}", i).to_string())
}
fn disasm_pop_simple(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(4).unwrap();
    assert!(opc == 0x3);
    let i = slice.get_next_int(4).unwrap();
    Some(format!("POP s{}", i).to_string())
}
fn disasm_xchg3(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(4).unwrap();
    assert!(opc == 0x4);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    let k = slice.get_next_int(4).unwrap();
    Some(format!("XCHG3 s{}, s{}, s{}", i, j, k).to_string())
}
fn disasm_xchg2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x50);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    Some(format!("XCHG2 s{}, s{}", i, j).to_string())
}
fn disasm_xcpu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x51);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    Some(format!("XCPU s{}, s{}", i, j).to_string())
}
fn disasm_puxc(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x52);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    Some(format!("PUXC s{}, s{}", i, j - 1).to_string())
}
fn disasm_push2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x53);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    Some(format!("PUSH2 s{}, s{}", i, j).to_string())
}
fn disasm_xc2pu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x541);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    let k = slice.get_next_int(4).unwrap();
    Some(format!("XC2PU s{}, s{}, s{}", i, j, k).to_string())
}
fn disasm_xcpuxc(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x542);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    let k = slice.get_next_int(4).unwrap();
    Some(format!("XCPUXC s{}, s{}, s{}", i, j, k - 1).to_string())
}
fn disasm_xcpu2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x543);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    let k = slice.get_next_int(4).unwrap();
    Some(format!("XCPU2 s{}, s{}, s{}", i, j, k).to_string())
}
fn disasm_puxc2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x544);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    let k = slice.get_next_int(4).unwrap();
    Some(format!("PUXC2 s{}, s{}, s{}", i, j - 1, k - 1).to_string())
}
fn disasm_puxcpu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x545);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    let k = slice.get_next_int(4).unwrap();
    Some(format!("PUXCPU s{}, s{}, s{}", i, j - 1, k - 1).to_string())
}
fn disasm_pu2xc(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x546);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    let k = slice.get_next_int(4).unwrap();
    Some(format!("PU2XC s{}, s{}, s{}", i, j - 1, k - 2).to_string())
}
fn disasm_push3(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x547);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    let k = slice.get_next_int(4).unwrap();
    Some(format!("PUSH3 s{}, s{}, s{}", i, j, k).to_string())
}
fn disasm_blkswap(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x55);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    Some(format!("BLKSWAP s{}, s{}", i, j).to_string())
}
fn disasm_push(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x56);
    let ii = slice.get_next_int(8).unwrap();
    Some(format!("PUSH s{}", ii).to_string())
}
fn disasm_pop(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x57);
    let ii = slice.get_next_int(8).unwrap();
    Some(format!("POP s{}", ii).to_string())
}
fn disasm_rot(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x58);
    Some("ROT".to_string())
}
fn disasm_rotrev(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x59);
    Some("ROTREV".to_string())
}
fn disasm_swap2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x5a);
    Some("SWAP2".to_string())
}
fn disasm_drop2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x5b);
    Some("DROP2".to_string())
}
fn disasm_dup2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x5c);
    Some("DUP2".to_string())
}
fn disasm_over2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x5d);
    Some("OVER2".to_string())
}
fn disasm_reverse(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x5e);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    Some(format!("REVERSE {}, {}", i + 2, j).to_string())
}
fn disasm_blkdrop(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x5f0);
    let i = slice.get_next_int(4).unwrap();
    Some(format!("BLKDROP {}", i).to_string())
}
fn disasm_blkpush(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x5f);
    let i = slice.get_next_int(4).unwrap();
    let j = slice.get_next_int(4).unwrap();
    Some(format!("BLKPUSH {}, {}", i, j).to_string())
}
fn disasm_pick(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x60);
    Some("PICK".to_string())
}
fn disasm_roll(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x61);
    Some("ROLL".to_string())
}
fn disasm_rollrev(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x62);
    Some("ROLLREV".to_string())
}
fn disasm_blkswx(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x63);
    Some("BLKSWX".to_string())
}
fn disasm_revx(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x64);
    Some("REVX".to_string())
}
fn disasm_dropx(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x65);
    Some("DROPX".to_string())
}
fn disasm_tuck(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x66);
    Some("TUCK".to_string())
}
fn disasm_xchgx(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x67);
    Some("XCHGX".to_string())
}
fn disasm_depth(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x68);
    Some("DEPTH".to_string())
}
fn disasm_chkdepth(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x69);
    Some("CHKDEPTH".to_string())
}
fn disasm_onlytopx(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x6a);
    Some("ONLYTOPX".to_string())
}
fn disasm_onlyx(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x6b);
    Some("ONLYX".to_string())
}
fn disasm_blkdrop2(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x6c);
    let i = slice.get_next_int(4).unwrap();
    assert!(i > 0);
    let j = slice.get_next_int(4).unwrap();
    Some(format!("BLKDROP2 {}, {}", i, j).to_string())
}
fn disasm_null(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x6d);
    Some("NULL".to_string())
}
fn disasm_isnull(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x6e);
    Some("ISNULL".to_string())
}
fn disasm_tuple_create(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x6f0);
    let k = slice.get_next_int(4).unwrap();
    Some(format!("TUPLE {}", k).to_string())
}
fn disasm_tuple_index(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x6f1);
    let k = slice.get_next_int(4).unwrap();
    Some(format!("INDEX {}", k).to_string())
}
fn disasm_tuple_un(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x6f2);
    let k = slice.get_next_int(4).unwrap();
    Some(format!("UNTUPLE {}", k).to_string())
}
fn disasm_tuple_unpackfirst(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x6f3);
    let k = slice.get_next_int(4).unwrap();
    Some(format!("UNPACKFIRST {}", k).to_string())
}
fn disasm_tuple_explode(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x6f4);
    let n = slice.get_next_int(4).unwrap();
    Some(format!("EXPLODE {}", n).to_string())
}
fn disasm_tuple_setindex(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x6f5);
    let k = slice.get_next_int(4).unwrap();
    Some(format!("SETINDEX {}", k).to_string())
}
fn disasm_tuple_index_quiet(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x6f6);
    let k = slice.get_next_int(4).unwrap();
    Some(format!("INDEXQ {}", k).to_string())
}
fn disasm_tuple_setindex_quiet(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0x6f7);
    let k = slice.get_next_int(4).unwrap();
    Some(format!("SETINDEXQ {}", k).to_string())
}
fn disasm_tuple_createvar(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f80);
    Some("INDEXVAR".to_string())
}
fn disasm_tuple_indexvar(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f81);
    Some("INDEXVAR".to_string())
}
fn disasm_tuple_untuplevar(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f82);
    Some("UNTUPLEVAR".to_string())
}
fn disasm_tuple_unpackfirstvar(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f83);
    Some("UNPACKFIRSTVAR".to_string())
}
fn disasm_tuple_explodevar(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f84);
    Some("EXPLODEVAR".to_string())
}
fn disasm_tuple_setindexvar(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f85);
    Some("SETINDEXVAR".to_string())
}
fn disasm_tuple_indexvar_quiet(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f86);
    Some("INDEXVARQ".to_string())
}
fn disasm_tuple_setindexvar_quiet(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f87);
    Some("SETINDEXVARQ".to_string())
}
fn disasm_tuple_len(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f88);
    Some("TLEN".to_string())
}
fn disasm_tuple_len_quiet(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f89);
    Some("QTLEN".to_string())
}
fn disasm_istuple(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f8a);
    Some("ISTUPLE".to_string())
}
fn disasm_tuple_last(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f8b);
    Some("LAST".to_string())
}
fn disasm_tuple_push(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f8c);
    Some("TPUSH".to_string())
}
fn disasm_tuple_pop(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6f8d);
    Some("TPOP".to_string())
}
fn disasm_nullswapif(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6fa0);
    Some("NULLSWAPIF".to_string())
}
fn disasm_nullswapifnot(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0x6fa1);
    Some("NULLSWAPIFNOT".to_string())
}
fn disasm_nullrotrif(_slice: &mut SliceData) -> Option<String> { println!("nullrotrif"); None }
fn disasm_nullrotrifnot(_slice: &mut SliceData) -> Option<String> { println!("nullrotrifnot"); None }
fn disasm_nullswapif2(_slice: &mut SliceData) -> Option<String> { println!("nullswapif2"); None }
fn disasm_nullswapifnot2(_slice: &mut SliceData) -> Option<String> { println!("nullswapifnot2"); None }
fn disasm_nullrotrif2(_slice: &mut SliceData) -> Option<String> { println!("nullrotrif2"); None }
fn disasm_nullrotrifnot2(_slice: &mut SliceData) -> Option<String> { println!("nullrotrifnot2"); None }
fn disasm_tuple_index2(_slice: &mut SliceData) -> Option<String> { println!("tuple_index2"); None }
fn disasm_tuple_index3(_slice: &mut SliceData) -> Option<String> { println!("tuple_index3"); None }
fn disasm_pushint(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(0x70 <= opc && opc < 0x82);
    let mut x: i16 = 0;
    if opc <= 0x7a {
        x = opc as i16 - 0x70;
    } else if opc < 0x80 {
        x = -(opc as i16 - 0x7f + 1);
    } else if opc == 0x80 {
        x = slice.get_next_int(8).unwrap() as i16;
    } else if opc == 0x81 {
        x = slice.get_next_int(16).unwrap() as i16;
    }
    Some(format!("PUSHINT {}", x).to_string())
}
fn disasm_pushint_big(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x82);
    let l = slice.get_next_int(5).unwrap() as usize;
    assert!(l < 31);
    let n = 8 * l + 19;
    let xxx = slice.get_next_slice(n).unwrap();
    Some(format!("PUSHINT TODO {}", xxx.into_cell().to_hex_string(false)).to_string())
}
fn disasm_pushpow2(_slice: &mut SliceData) -> Option<String> { println!("pushpow2"); None }
fn disasm_pushnan(_slice: &mut SliceData) -> Option<String> { println!("pushnan"); None }
fn disasm_pushpow2dec(_slice: &mut SliceData) -> Option<String> { println!("pushpow2dec"); None }
fn disasm_pushnegpow2(_slice: &mut SliceData) -> Option<String> { println!("pushnegpow2"); None }
fn disasm_pushref(_slice: &mut SliceData) -> Option<String> { println!("pushref"); None }
fn disasm_pushrefslice(_slice: &mut SliceData) -> Option<String> { println!("pushrefslice"); None }
fn disasm_pushrefcont(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x8a);
    // TODO: shrink?
    Some("PUSHREFCONT".to_string())
}
fn disasm_pushslice_short(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x8b);
    let x = slice.get_next_int(4).unwrap();
    let bitstring = slice.get_next_slice(x as usize * 8 + 4).unwrap();
    Some(format!("PUSHSLICE {}", bitstring.to_hex_string()).to_string())
}
fn disasm_pushslice_mid(_slice: &mut SliceData) -> Option<String> { println!("pushslice_mid"); None }
fn disasm_pushslice_long(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0x8d);
    let r = slice.get_next_int(3).unwrap();
    assert!(r == 0); // TODO
    let xx = slice.get_next_int(7).unwrap();
    let bitstring = slice.get_next_slice(xx as usize * 8 + 6).unwrap();
    Some(format!("PUSHSLICE {}", bitstring.to_hex_string()).to_string())
}
fn disasm_pushcont_long(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(7).unwrap();
    assert!(opc << 1 == 0x8e);
    let r = slice.get_next_int(2).unwrap() as usize;
    let xx = slice.get_next_int(7).unwrap();
    let mut disasm = "".to_string();
    for i in 0..r {
        let c = slice.reference(i as usize).unwrap();
        let mut s = SliceData::from(c);
        disasm += &indent(disassemble(&mut s, false));
    }
    if r > 0 {
        slice.shrink_references(0..r);
    }
    let mut body = slice.get_next_slice(xx as usize * 8).unwrap();
    disasm += &indent(disassemble(&mut body, false));
    Some(format!("PUSHCONT {{\n{}}}", disasm).to_string())
}
fn disasm_pushcont_short(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(4).unwrap();
    assert!(opc == 0x9);
    let x = slice.get_next_int(4).unwrap();
    let mut body = slice.get_next_slice(x as usize * 8).unwrap();
    let d = indent(disassemble(&mut body, false));
    Some(format!("PUSHCONT {{\n{}}}", d).to_string())
}
fn disasm_add<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa0);
    Some(format!("ADD{}", T::suffix()).to_string())
}
fn disasm_sub<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa1);
    Some(format!("SUB{}", T::suffix()).to_string())
}
fn disasm_subr<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa2);
    Some(format!("SUBR{}", T::suffix()).to_string())
}
fn disasm_negate<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa3);
    Some(format!("NEGATE{}", T::suffix()).to_string())
}
fn disasm_inc<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa4);
    Some(format!("INC{}", T::suffix()).to_string())
}
fn disasm_dec<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa5);
    Some(format!("DEC{}", T::suffix()).to_string())
}
fn disasm_addconst<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa6);
    let cc = slice.get_next_int(8).unwrap() as i8;
    Some(format!("ADDCONST{} {}", T::suffix(), cc).to_string())
}
fn disasm_mulconst<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa7);
    let cc = slice.get_next_int(8).unwrap() as i8;
    Some(format!("MULCONST{} {}", T::suffix(), cc).to_string())
}
fn disasm_mul<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa8);
    Some(format!("MUL{}", T::suffix()).to_string())
}
fn disasm_divmod<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xa9);
    let opc2 = slice.get_next_int(8).unwrap();
    match opc2 {
        0x04 => Some(format!("DIV{}", T::suffix()).to_string()),
        0x05 => Some(format!("DIVR{}", T::suffix()).to_string()),
        0x06 => Some(format!("DIVC{}", T::suffix()).to_string()),
        0x08 => Some(format!("MOD{}", T::suffix()).to_string()),
        0x0c => Some(format!("DIVMOD{}", T::suffix()).to_string()),
        0x0d => Some(format!("DIVMODR{}", T::suffix()).to_string()),
        0x0e => Some(format!("DIVMODC{}", T::suffix()).to_string()),
        0x24 => Some(format!("RSHIFT{}", T::suffix()).to_string()),
        0x34 => {
            let tt = slice.get_next_int(8).unwrap();
            Some(format!("RSHIFT{} {}", T::suffix(), tt + 1).to_string())
        },
        0x38 => {
            let tt = slice.get_next_int(8).unwrap();
            Some(format!("MODPOW2{} {}", T::suffix(), tt + 1).to_string())
        },
        0x84 => Some(format!("MULDIV{}", T::suffix()).to_string()),
        0x85 => Some(format!("MULDIVR{}", T::suffix()).to_string()),
        0x8c => Some(format!("MULDIVMOD{}", T::suffix()).to_string()),
        0xa4 => Some(format!("MULRSHIFT{}", T::suffix()).to_string()),
        0xa5 => Some(format!("MULRSHIFTR{}", T::suffix()).to_string()),
        0xb4 => {
            let tt = slice.get_next_int(8).unwrap();
            Some(format!("MULRSHIFT{} {}", T::suffix(), tt + 1).to_string())
        },
        0xb5 => {
            let tt = slice.get_next_int(8).unwrap();
            Some(format!("MULRSHIFTR{} {}", T::suffix(), tt + 1).to_string())
        },
        0xc4 => Some(format!("LSHIFTDIV{}", T::suffix()).to_string()),
        0xc5 => Some(format!("LSHIFTDIVR{}", T::suffix()).to_string()),
        0xd4 => {
            let tt = slice.get_next_int(8).unwrap();
            Some(format!("LSHIFTDIV{} {}", T::suffix(), tt + 1).to_string())
        },
        0xd5 => {
            let tt = slice.get_next_int(8).unwrap();
            Some(format!("LSHIFTDIVR{} {}", T::suffix(), tt + 1).to_string())
        },
        _ => {
            println!("divmod? {:x}", opc2);
            None
        }
    }
}
fn disasm_lshift<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xac);
    Some(format!("LSHIFT{}", T::suffix()).to_string())
}
fn disasm_rshift<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xad);
    Some(format!("RSHIFT{}", T::suffix()).to_string())
}
fn disasm_pow2<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xae);
    Some(format!("POW2{}", T::suffix()).to_string())
}
fn disasm_and<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xb0);
    Some(format!("AND{}", T::suffix()).to_string())
}
fn disasm_or<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xb1);
    Some(format!("OR{}", T::suffix()).to_string())
}
fn disasm_xor<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xb2);
    Some(format!("XOR{}", T::suffix()).to_string())
}
fn disasm_not<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xb3);
    Some(format!("NOT{}", T::suffix()).to_string())
}
fn disasm_fits<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xb4);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("FITS{} {}", T::suffix(), cc + 1).to_string())
}
fn disasm_ufits<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xb5);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("UFITS{} {}", T::suffix(), cc + 1).to_string())
}
fn disasm_fitsx<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xb600);
    Some(format!("FITSX{}", T::suffix()).to_string())
}
fn disasm_ufitsx<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xb601);
    Some(format!("UFITSX{}", T::suffix()).to_string())
}
fn disasm_bitsize<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xb602);
    Some(format!("BITSIZE{}", T::suffix()).to_string())
}
fn disasm_ubitsize<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xb603);
    Some(format!("UBITSIZE{}", T::suffix()).to_string())
}
fn disasm_min<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xb608);
    Some(format!("MIN{}", T::suffix()).to_string())
}
fn disasm_max<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xb609);
    Some(format!("MAX{}", T::suffix()).to_string())
}
fn disasm_minmax<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xb60a);
    Some(format!("MINMAX{}", T::suffix()).to_string())
}
fn disasm_abs<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xb60b);
    Some(format!("ABS{}", T::suffix()).to_string())
}
fn disasm_sgn<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xb8);
    Some(format!("SGN{}", T::suffix()).to_string())
}
fn disasm_less<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xb9);
    Some(format!("LESS{}", T::suffix()).to_string())
}
fn disasm_equal<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xba);
    Some(format!("EQUAL{}", T::suffix()).to_string())
}
fn disasm_leq<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xbb);
    Some(format!("LEQ{}", T::suffix()).to_string())
}
fn disasm_greater<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xbc);
    Some(format!("GREATER{}", T::suffix()).to_string())
}
fn disasm_neq<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xbd);
    Some(format!("NEQ{}", T::suffix()).to_string())
}
fn disasm_geq<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xbe);
    Some(format!("GEQ{}", T::suffix()).to_string())
}
fn disasm_cmp<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xbf);
    Some(format!("CMP{}", T::suffix()).to_string())
}
fn disasm_eqint<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xc0);
    let yy = slice.get_next_int(8).unwrap();
    Some(format!("EQINT{} {}", T::suffix(), yy).to_string())
}
fn disasm_lessint<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xc1);
    let yy = slice.get_next_int(8).unwrap();
    Some(format!("LESSINT{} {}", T::suffix(), yy).to_string())
}
fn disasm_gtint<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xc2);
    let yy = slice.get_next_int(8).unwrap();
    Some(format!("GTINT{} {}", T::suffix(), yy).to_string())
}
fn disasm_neqint<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xc3);
    let yy = slice.get_next_int(8).unwrap();
    Some(format!("NEQINT{} {}", T::suffix(), yy).to_string())
}
fn disasm_isnan(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xc4);
    Some("ISNAN".to_string())
}
fn disasm_chknan(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xc5);
    Some("CHKNAN".to_string())
}
fn disasm_sempty(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xc700);
    Some("SEMPTY".to_string())
}
fn disasm_sdempty(_slice: &mut SliceData) -> Option<String> { println!("sdempty"); None }
fn disasm_srempty(_slice: &mut SliceData) -> Option<String> { println!("srempty"); None }
fn disasm_sdfirst(_slice: &mut SliceData) -> Option<String> { println!("sdfirst"); None }
fn disasm_sdlexcmp(_slice: &mut SliceData) -> Option<String> { println!("sdlexcmp"); None }
fn disasm_sdeq(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xc705);
    Some("SDEQ".to_string())
}
fn disasm_sdpfx(_slice: &mut SliceData) -> Option<String> { println!("sdpfx"); None }
fn disasm_sdpfxrev(_slice: &mut SliceData) -> Option<String> { println!("sdpfxrev"); None }
fn disasm_sdppfx(_slice: &mut SliceData) -> Option<String> { println!("sdppfx"); None }
fn disasm_sdppfxrev(_slice: &mut SliceData) -> Option<String> { println!("sdppfxrev"); None }
fn disasm_sdsfx(_slice: &mut SliceData) -> Option<String> { println!("sdsfx"); None }
fn disasm_sdsfxrev(_slice: &mut SliceData) -> Option<String> { println!("sdsfxrev"); None }
fn disasm_sdpsfx(_slice: &mut SliceData) -> Option<String> { println!("sdpsfx"); None }
fn disasm_sdpsfxrev(_slice: &mut SliceData) -> Option<String> { println!("sdpsfxrev"); None }
fn disasm_sdcntlead0(_slice: &mut SliceData) -> Option<String> { println!("sdcntlead0"); None }
fn disasm_sdcntlead1(_slice: &mut SliceData) -> Option<String> { println!("sdcntlead1"); None }
fn disasm_sdcnttrail0(_slice: &mut SliceData) -> Option<String> { println!("sdcnttrail0"); None }
fn disasm_sdcnttrail1(_slice: &mut SliceData) -> Option<String> { println!("sdcnttrail1"); None }
fn disasm_newc(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xc8);
    Some("NEWC".to_string())
}
fn disasm_endc(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xc9);
    Some("ENDC".to_string())
}
fn disasm_sti(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xca);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("STI {}", cc + 1).to_string())
}
fn disasm_stu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xcb);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("STU {}", cc + 1).to_string())
}
fn disasm_stref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xcc);
    Some("STREF".to_string())
}
fn disasm_endcst(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xcd);
    Some("STBREFR".to_string())
}
fn disasm_stslice(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xce);
    Some("STSLICE".to_string())
}
fn disasm_stix(_slice: &mut SliceData) -> Option<String> { println!("stix"); None }
fn disasm_stux(_slice: &mut SliceData) -> Option<String> { println!("stux"); None }
fn disasm_stixr(_slice: &mut SliceData) -> Option<String> { println!("stixr"); None }
fn disasm_stuxr(_slice: &mut SliceData) -> Option<String> { println!("stuxr"); None }
fn disasm_stixq(_slice: &mut SliceData) -> Option<String> { println!("stixq"); None }
fn disasm_stuxq(_slice: &mut SliceData) -> Option<String> { println!("stuxq"); None }
fn disasm_stixrq(_slice: &mut SliceData) -> Option<String> { println!("stixrq"); None }
fn disasm_stuxrq(_slice: &mut SliceData) -> Option<String> { println!("stuxrq"); None }
fn disasm_stir(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf0a);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("STIR {}", cc + 1).to_string())
}
fn disasm_stur(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf0b);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("STUR {}", cc + 1).to_string())
}
fn disasm_stiq(_slice: &mut SliceData) -> Option<String> { println!("stiq"); None }
fn disasm_stuq(_slice: &mut SliceData) -> Option<String> { println!("stuq"); None }
fn disasm_stirq(_slice: &mut SliceData) -> Option<String> { println!("stirq"); None }
fn disasm_sturq(_slice: &mut SliceData) -> Option<String> { println!("sturq"); None }
fn disasm_stbref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf11);
    Some("STBREF".to_string())
}
fn disasm_stb(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf13);
    Some("STB".to_string())
}
fn disasm_strefr(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf14);
    Some("STREFR".to_string())
}
fn disasm_stslicer(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf16);
    Some("STSLICER".to_string())
} 
fn disasm_stbr(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf17);
    Some("STBR".to_string())
}
fn disasm_strefq(_slice: &mut SliceData) -> Option<String> { println!("strefq"); None }
fn disasm_stbrefq(_slice: &mut SliceData) -> Option<String> { println!("stbrefq"); None }
fn disasm_stsliceq(_slice: &mut SliceData) -> Option<String> { println!("stsliceq"); None }
fn disasm_stbq(_slice: &mut SliceData) -> Option<String> { println!("stbq"); None }
fn disasm_strefrq(_slice: &mut SliceData) -> Option<String> { println!("strefrq"); None }
fn disasm_stbrefrq(_slice: &mut SliceData) -> Option<String> { println!("stbrefrq"); None }
fn disasm_stslicerq(_slice: &mut SliceData) -> Option<String> { println!("stslicerq"); None }
fn disasm_stbrq(_slice: &mut SliceData) -> Option<String> { println!("stbrq"); None }
fn disasm_strefconst(_slice: &mut SliceData) -> Option<String> { println!("strefconst"); None }
fn disasm_stref2const(_slice: &mut SliceData) -> Option<String> { println!("stref2const"); None }
fn disasm_endxc(_slice: &mut SliceData) -> Option<String> { println!("endxc"); None }
fn disasm_stile4(_slice: &mut SliceData) -> Option<String> { println!("stile4"); None }
fn disasm_stule4(_slice: &mut SliceData) -> Option<String> { println!("stule4"); None }
fn disasm_stile8(_slice: &mut SliceData) -> Option<String> { println!("stile8"); None }
fn disasm_stule8(_slice: &mut SliceData) -> Option<String> { println!("stule8"); None }
fn disasm_bdepth(_slice: &mut SliceData) -> Option<String> { println!("bdepth"); None }
fn disasm_bbits(_slice: &mut SliceData) -> Option<String> { println!("bbits"); None }
fn disasm_brefs(_slice: &mut SliceData) -> Option<String> { println!("brefs"); None }
fn disasm_bbitrefs(_slice: &mut SliceData) -> Option<String> { println!("bbitrefs"); None }
fn disasm_brembits(_slice: &mut SliceData) -> Option<String> { println!("brembits"); None }
fn disasm_bremrefs(_slice: &mut SliceData) -> Option<String> { println!("bremrefs"); None }
fn disasm_brembitrefs(_slice: &mut SliceData) -> Option<String> { println!("brembitrefs"); None }
fn disasm_bchkbits_short(_slice: &mut SliceData) -> Option<String> { println!("bchkbits_short"); None }
fn disasm_bchkbits_long(_slice: &mut SliceData) -> Option<String> { println!("bchkbits_long"); None }
fn disasm_bchkrefs(_slice: &mut SliceData) -> Option<String> { println!("bchkrefs"); None }
fn disasm_bchkbitrefs(_slice: &mut SliceData) -> Option<String> { println!("bchkbitrefs"); None }
fn disasm_bchkbitsq_short(_slice: &mut SliceData) -> Option<String> { println!("bchkbitsq_short"); None }
fn disasm_bchkbitsq_long(_slice: &mut SliceData) -> Option<String> { println!("bchkbitsq_long"); None }
fn disasm_bchkrefsq(_slice: &mut SliceData) -> Option<String> { println!("bchkrefsq"); None }
fn disasm_bchkbitrefsq(_slice: &mut SliceData) -> Option<String> { println!("bchkbitrefsq"); None }
fn disasm_stzeroes(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf40);
    Some("STZEROES".to_string())
}
fn disasm_stones(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf41);
    Some("STONES".to_string())
}
fn disasm_stsame(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xcf42);
    Some("STSAME".to_string())
}
fn disasm_stsliceconst(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(9).unwrap();
    assert!(opc << 3 == 0xcf8);
    let x = slice.get_next_int(2).unwrap();
    assert!(x == 0);
    let y = slice.get_next_int(3).unwrap();
    let sss = slice.get_next_slice(y as usize * 8 + 2).unwrap();
    Some(format!("STSLICECONST {}", sss.into_cell().to_hex_string(false)).to_string())
}
fn disasm_ctos(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xd0);
    Some("CTOS".to_string())
}
fn disasm_ends(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xd1);
    Some("ENDS".to_string())
}
fn disasm_ldi(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xd2);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("LDI {}", cc + 1).to_string())
}
fn disasm_ldu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xd3);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("LDU {}", cc + 1).to_string())
}
fn disasm_ldref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xd4);
    Some("LDREF".to_string())
}
fn disasm_ldrefrtos(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xd5);
    Some("LDREFRTOS".to_string())
}
fn disasm_ldslice(_slice: &mut SliceData) -> Option<String> { println!("ldslice"); None }
fn disasm_ldix(_slice: &mut SliceData) -> Option<String> { println!("ldix"); None }
fn disasm_ldux(_slice: &mut SliceData) -> Option<String> { println!("ldux"); None }
fn disasm_pldix(_slice: &mut SliceData) -> Option<String> { println!("pldix"); None }
fn disasm_pldux(_slice: &mut SliceData) -> Option<String> { println!("pldux"); None }
fn disasm_ldixq(_slice: &mut SliceData) -> Option<String> { println!("ldixq"); None }
fn disasm_lduxq(_slice: &mut SliceData) -> Option<String> { println!("lduxq"); None }
fn disasm_pldixq(_slice: &mut SliceData) -> Option<String> { println!("pldixq"); None }
fn disasm_plduxq(_slice: &mut SliceData) -> Option<String> { println!("plduxq"); None }
fn disasm_pldi(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd70a);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("PLDI {}", cc + 1).to_string())
}
fn disasm_pldu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd70b);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("PLDU {}", cc + 1).to_string())
}
fn disasm_ldiq(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd70c);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("LDIQ {}", cc + 1).to_string())
}
fn disasm_lduq(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd70d);
    let cc = slice.get_next_int(8).unwrap();
    Some(format!("LDUQ {}", cc + 1).to_string())
}
fn disasm_pldiq(_slice: &mut SliceData) -> Option<String> { println!("pldiq"); None }
fn disasm_plduq(_slice: &mut SliceData) -> Option<String> { println!("plduq"); None }
fn disasm_plduz(_slice: &mut SliceData) -> Option<String> { println!("plduz"); None }
fn disasm_ldslicex(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd718);
    Some("LDSLICEX".to_string())
}
fn disasm_pldslicex(_slice: &mut SliceData) -> Option<String> { println!("pldslicex"); None }
fn disasm_ldslicexq(_slice: &mut SliceData) -> Option<String> { println!("ldslicexq"); None }
fn disasm_pldslicexq(_slice: &mut SliceData) -> Option<String> { println!("pldslicexq"); None }
fn disasm_pldslice(_slice: &mut SliceData) -> Option<String> { println!("pldslice"); None }
fn disasm_ldsliceq(_slice: &mut SliceData) -> Option<String> { println!("ldsliceq"); None }
fn disasm_pldsliceq(_slice: &mut SliceData) -> Option<String> { println!("pldsliceq"); None }
fn disasm_sdskipfirst(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd721);
    Some("SDSKIPFIRST".to_string())
}
fn disasm_sdcutlast(_slice: &mut SliceData) -> Option<String> { println!("sdcutlast"); None }
fn disasm_sdskiplast(_slice: &mut SliceData) -> Option<String> { println!("sdskiplast"); None }
fn disasm_sdsubstr(_slice: &mut SliceData) -> Option<String> { println!("sdsubstr"); None }
fn disasm_sdbeginsx(_slice: &mut SliceData) -> Option<String> { println!("sdbeginsx"); None }
fn disasm_sdbeginsxq(_slice: &mut SliceData) -> Option<String> { println!("sdbeginsxq"); None }
fn disasm_sdbegins(_slice: &mut SliceData) -> Option<String> { println!("sdbegins"); None }
fn disasm_sdbeginsq(_slice: &mut SliceData) -> Option<String> { println!("sdbeginsq"); None }
fn disasm_scutfirst(_slice: &mut SliceData) -> Option<String> { println!("scutfirst"); None }
fn disasm_sskipfirst(_slice: &mut SliceData) -> Option<String> { println!("sskipfirst"); None }
fn disasm_scutlast(_slice: &mut SliceData) -> Option<String> { println!("scutlast"); None }
fn disasm_sskiplast(_slice: &mut SliceData) -> Option<String> { println!("sskiplast"); None }
fn disasm_subslice(_slice: &mut SliceData) -> Option<String> { println!("subslice"); None }
fn disasm_split(_slice: &mut SliceData) -> Option<String> { println!("split"); None }
fn disasm_splitq(_slice: &mut SliceData) -> Option<String> { println!("splitq"); None }
fn disasm_xctos(_slice: &mut SliceData) -> Option<String> { println!("xctos"); None }
fn disasm_xload(_slice: &mut SliceData) -> Option<String> { println!("xload"); None }
fn disasm_xloadq(_slice: &mut SliceData) -> Option<String> { println!("xloadq"); None }
fn disasm_schkbits(_slice: &mut SliceData) -> Option<String> { println!("schkbits"); None }
fn disasm_schkrefs(_slice: &mut SliceData) -> Option<String> { println!("schkrefs"); None }
fn disasm_schkbitrefs(_slice: &mut SliceData) -> Option<String> { println!("schkbitrefs"); None }
fn disasm_schkbitsq(_slice: &mut SliceData) -> Option<String> { println!("schkbitsq"); None }
fn disasm_schkrefsq(_slice: &mut SliceData) -> Option<String> { println!("schkrefsq"); None }
fn disasm_schkbitrefsq(_slice: &mut SliceData) -> Option<String> { println!("schkbitrefsq"); None }
fn disasm_pldrefvar(_slice: &mut SliceData) -> Option<String> { println!("pldrefvar"); None }
fn disasm_sbits(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd749);
    Some("SBITS".to_string())
}
fn disasm_srefs(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd74a);
    Some("SREFS".to_string())
}
fn disasm_sbitrefs(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd74b);
    Some("SBITREFS".to_string())
}
fn disasm_pldref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd74c);
    Some("PLDREF".to_string())
}
fn disasm_pldrefidx(_slice: &mut SliceData) -> Option<String> { println!("pldrefidx"); None }
fn disasm_ldile4(_slice: &mut SliceData) -> Option<String> { println!("ldile4"); None } 
fn disasm_ldule4(_slice: &mut SliceData) -> Option<String> { println!("ldule4"); None } 
fn disasm_ldile8(_slice: &mut SliceData) -> Option<String> { println!("ldile8"); None } 
fn disasm_ldule8(_slice: &mut SliceData) -> Option<String> { println!("ldule8"); None } 
fn disasm_pldile4(_slice: &mut SliceData) -> Option<String> { println!("pldile4"); None }
fn disasm_pldule4(_slice: &mut SliceData) -> Option<String> { println!("pldule4"); None }
fn disasm_pldile8(_slice: &mut SliceData) -> Option<String> { println!("pldile8"); None }
fn disasm_pldule8(_slice: &mut SliceData) -> Option<String> { println!("pldule8"); None }
fn disasm_ldile4q(_slice: &mut SliceData) -> Option<String> { println!("ldile4q"); None } 
fn disasm_ldule4q(_slice: &mut SliceData) -> Option<String> { println!("ldule4q"); None } 
fn disasm_ldile8q(_slice: &mut SliceData) -> Option<String> { println!("ldile8q"); None } 
fn disasm_ldule8q(_slice: &mut SliceData) -> Option<String> { println!("ldule8q"); None } 
fn disasm_pldile4q(_slice: &mut SliceData) -> Option<String> { println!("pldile4q"); None }
fn disasm_pldule4q(_slice: &mut SliceData) -> Option<String> { println!("pldule4q"); None }
fn disasm_pldile8q(_slice: &mut SliceData) -> Option<String> { println!("pldile8q"); None }
fn disasm_pldule8q(_slice: &mut SliceData) -> Option<String> { println!("pldule8q"); None }
fn disasm_ldzeroes(_slice: &mut SliceData) -> Option<String> { println!("ldzeroes"); None }
fn disasm_ldones(_slice: &mut SliceData) -> Option<String> { println!("ldones"); None }
fn disasm_ldsame(_slice: &mut SliceData) -> Option<String> { println!("ldsame"); None }
fn disasm_sdepth(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xd764);
    Some("SDEPTH".to_string())
}
fn disasm_cdepth(_slice: &mut SliceData) -> Option<String> { println!("cdepth"); None }
fn disasm_callx(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xd8);
    Some("CALLX".to_string())
}
fn disasm_jmpx(_slice: &mut SliceData) -> Option<String> { println!("jmpx"); None }
fn disasm_callxargs(_slice: &mut SliceData) -> Option<String> { println!("callxargs"); None }
fn disasm_jmpxargs(_slice: &mut SliceData) -> Option<String> { println!("jmpxargs"); None }
fn disasm_retargs(_slice: &mut SliceData) -> Option<String> { println!("retargs"); None }
fn disasm_ret(_slice: &mut SliceData) -> Option<String> { println!("ret"); None }
fn disasm_retalt(_slice: &mut SliceData) -> Option<String> { println!("retalt"); None }
fn disasm_retbool(_slice: &mut SliceData) -> Option<String> { println!("retbool"); None }
fn disasm_callcc(_slice: &mut SliceData) -> Option<String> { println!("callcc"); None }
fn disasm_jmpxdata(_slice: &mut SliceData) -> Option<String> { println!("jmpxdata"); None }
fn disasm_callccargs(_slice: &mut SliceData) -> Option<String> { println!("callccargs"); None }
fn disasm_callxva(_slice: &mut SliceData) -> Option<String> { println!("callxva"); None }
fn disasm_retva(_slice: &mut SliceData) -> Option<String> { println!("retva"); None }
fn disasm_jmpxva(_slice: &mut SliceData) -> Option<String> { println!("jmpxva"); None }
fn disasm_callccva(_slice: &mut SliceData) -> Option<String> { println!("callccva"); None }
fn disasm_callref(_slice: &mut SliceData) -> Option<String> { println!("callref"); None }
fn disasm_jmpref(_slice: &mut SliceData) -> Option<String> { println!("jmpref"); None }
fn disasm_jmprefdata(_slice: &mut SliceData) -> Option<String> { println!("jmprefdata"); None }
fn disasm_retdata(_slice: &mut SliceData) -> Option<String> { println!("retdata"); None }
fn disasm_if(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xde);
    Some("IF".to_string())
}
fn disasm_ifret(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xdc);
    Some("IFRET".to_string())
}
fn disasm_ifnotret(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xdd);
    Some("IFNOTRET".to_string())
}
fn disasm_ifnot(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xdf);
    Some("IFNOT".to_string())
}
fn disasm_ifjmp(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe0);
    Some("IFJMP".to_string())
}
fn disasm_ifnotjmp(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe1);
    Some("IFNOTJMP".to_string())
}
fn disasm_ifelse(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe2);
    Some("IFELSE".to_string())
}
fn disasm_ifref(_slice: &mut SliceData) -> Option<String> { println!("ifref"); None }
fn disasm_ifnotref(_slice: &mut SliceData) -> Option<String> { println!("ifnotref"); None }
fn disasm_ifjmpref(_slice: &mut SliceData) -> Option<String> { println!("ifjmpref"); None }
fn disasm_ifnotjmpref(_slice: &mut SliceData) -> Option<String> { println!("ifnotjmpref"); None }
fn disasm_condsel(_slice: &mut SliceData) -> Option<String> { println!("condsel"); None }
fn disasm_condselchk(_slice: &mut SliceData) -> Option<String> { println!("condselchk"); None }
fn disasm_ifretalt(_slice: &mut SliceData) -> Option<String> { println!("ifretalt"); None }
fn disasm_ifnotretalt(_slice: &mut SliceData) -> Option<String> { println!("ifnotretalt"); None }
fn disasm_ifrefelse(_slice: &mut SliceData) -> Option<String> { println!("ifrefelse"); None }
fn disasm_ifelseref(_slice: &mut SliceData) -> Option<String> { println!("ifelseref"); None }
fn disasm_ifrefelseref(_slice: &mut SliceData) -> Option<String> { println!("ifrefelseref"); None }
fn disasm_repeat_break(_slice: &mut SliceData) -> Option<String> { println!("repeat_break"); None }
fn disasm_repeatend_break(_slice: &mut SliceData) -> Option<String> { println!("repeatend_break"); None }
fn disasm_until_break(_slice: &mut SliceData) -> Option<String> { println!("until_break"); None }
fn disasm_untilend_break(_slice: &mut SliceData) -> Option<String> { println!("untilend_break"); None }
fn disasm_while_break(_slice: &mut SliceData) -> Option<String> { println!("while_break"); None }
fn disasm_whileend_break(_slice: &mut SliceData) -> Option<String> { println!("whileend_break"); None }
fn disasm_again_break(_slice: &mut SliceData) -> Option<String> { println!("again_break"); None }
fn disasm_againend_break(_slice: &mut SliceData) -> Option<String> { println!("againend_break"); None }
fn disasm_ifbitjmp(_slice: &mut SliceData) -> Option<String> { println!("ifbitjmp"); None }
fn disasm_ifnbitjmp(_slice: &mut SliceData) -> Option<String> { println!("ifnbitjmp"); None }
fn disasm_ifbitjmpref(_slice: &mut SliceData) -> Option<String> { println!("ifbitjmpref"); None }
fn disasm_ifnbitjmpref(_slice: &mut SliceData) -> Option<String> { println!("ifnbitjmpref"); None }
fn disasm_repeat(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe4);
    Some("REPEAT".to_string())
}
fn disasm_repeatend(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe5);
    Some("REPEATEND".to_string())
}
fn disasm_until(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe6);
    Some("UNTIL".to_string())
}
fn disasm_untilend(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe7);
    Some("UNTILEND".to_string())
}
fn disasm_while(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe8);
    Some("WHILE".to_string())
}
fn disasm_whileend(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xe9);
    Some("WHILEEND".to_string())
}
fn disasm_again(_slice: &mut SliceData) -> Option<String> { println!("again"); None }
fn disasm_againend(_slice: &mut SliceData) -> Option<String> { println!("againend"); None }
fn disasm_setcontargs(_slice: &mut SliceData) -> Option<String> { println!("setcontargs"); None }
fn disasm_returnargs(_slice: &mut SliceData) -> Option<String> { println!("returnargs"); None }
fn disasm_returnva(_slice: &mut SliceData) -> Option<String> { println!("returnva"); None }
fn disasm_setcontva(_slice: &mut SliceData) -> Option<String> { println!("setcontva"); None }
fn disasm_setnumvarargs(_slice: &mut SliceData) -> Option<String> { println!("setnumvarargs"); None }
fn disasm_bless(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xed1e);
    Some("BLESS".to_string())
}
fn disasm_blessva(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xed1f);
    Some("BLESSVARARGS".to_string())
}
fn disasm_pushctr(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0xed4);
    let i = slice.get_next_int(4).unwrap();
    Some(format!("PUSHCTR c{}", i).to_string())
}
fn disasm_popctr(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0xed5);
    let i = slice.get_next_int(4).unwrap();
    Some(format!("POPCTR c{}", i).to_string())
}
fn disasm_setcontctr(_slice: &mut SliceData) -> Option<String> { println!("setcontctr"); None }
fn disasm_setretctr(_slice: &mut SliceData) -> Option<String> { println!("setretctr"); None }
fn disasm_setaltctr(_slice: &mut SliceData) -> Option<String> { println!("setaltctr"); None }
fn disasm_popsave(_slice: &mut SliceData) -> Option<String> { println!("popsave"); None }
fn disasm_save(_slice: &mut SliceData) -> Option<String> { println!("save"); None }
fn disasm_savealt(_slice: &mut SliceData) -> Option<String> { println!("savealt"); None }
fn disasm_saveboth(_slice: &mut SliceData) -> Option<String> { println!("saveboth"); None }
fn disasm_pushctrx(_slice: &mut SliceData) -> Option<String> { println!("pushctrx"); None }
fn disasm_popctrx(_slice: &mut SliceData) -> Option<String> { println!("popctrx"); None }
fn disasm_setcontctrx(_slice: &mut SliceData) -> Option<String> { println!("setcontctrx"); None }
fn disasm_compos(_slice: &mut SliceData) -> Option<String> { println!("compos"); None }
fn disasm_composalt(_slice: &mut SliceData) -> Option<String> { println!("composalt"); None }
fn disasm_composboth(_slice: &mut SliceData) -> Option<String> { println!("composboth"); None }
fn disasm_atexit(_slice: &mut SliceData) -> Option<String> { println!("atexit"); None }
fn disasm_atexitalt(_slice: &mut SliceData) -> Option<String> { println!("atexitalt"); None }
fn disasm_setexitalt(_slice: &mut SliceData) -> Option<String> { println!("setexitalt"); None }
fn disasm_thenret(_slice: &mut SliceData) -> Option<String> { println!("thenret"); None }
fn disasm_thenretalt(_slice: &mut SliceData) -> Option<String> { println!("thenretalt"); None }
fn disasm_invert(_slice: &mut SliceData) -> Option<String> { println!("invert"); None }
fn disasm_booleval(_slice: &mut SliceData) -> Option<String> { println!("booleval"); None }
fn disasm_samealt(_slice: &mut SliceData) -> Option<String> { println!("samealt"); None }
fn disasm_samealt_save(_slice: &mut SliceData) -> Option<String> { println!("samealt_save"); None }
fn disasm_blessargs(_slice: &mut SliceData) -> Option<String> { println!("blessargs"); None }
fn disasm_call_short(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(8).unwrap();
    assert!(opc == 0xf0);
    let n = slice.get_next_int(8).unwrap();
    Some(format!("CALL {}", n).to_string())
}
fn disasm_call_long(_slice: &mut SliceData) -> Option<String> { println!("call_long"); None }
fn disasm_jmp(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(10).unwrap();
    assert!(opc << 2 == 0xf14);
    let n = slice.get_next_int(14).unwrap();
    Some(format!("JMPDICT {}", n).to_string())
}
fn disasm_prepare(_slice: &mut SliceData) -> Option<String> { println!("prepare"); None }
fn disasm_throw_short(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(10).unwrap();
    assert!(opc << 2 == 0xf20);
    let nn = slice.get_next_int(6).unwrap();
    Some(format!("THROW {}", nn).to_string())
}
fn disasm_throwif_short(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(10).unwrap();
    assert!(opc << 2 == 0xf24);
    let nn = slice.get_next_int(6).unwrap();
    Some(format!("THROWIF {}", nn).to_string())
}
fn disasm_throwifnot_short(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(10).unwrap();
    assert!(opc << 2 == 0xf28);
    let nn = slice.get_next_int(6).unwrap();
    Some(format!("THROWIFNOT {}", nn).to_string())
}
fn disasm_throw_long(_slice: &mut SliceData) -> Option<String> { println!("throw_long"); None }
fn disasm_throwarg(_slice: &mut SliceData) -> Option<String> { println!("throwarg"); None }
fn disasm_throwif_long(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(13).unwrap();
    assert!(opc << 3 == 0xf2d0);
    let nn = slice.get_next_int(11).unwrap();
    Some(format!("THROWIF {}", nn).to_string())
}
fn disasm_throwargif(_slice: &mut SliceData) -> Option<String> { println!("throwargif"); None }
fn disasm_throwifnot_long(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(13).unwrap();
    assert!(opc << 3 == 0xf2e0);
    let nn = slice.get_next_int(11).unwrap();
    Some(format!("THROWIFNOT {}", nn).to_string())
}
fn disasm_throwargifnot(_slice: &mut SliceData) -> Option<String> { println!("throwargifnot"); None }
fn disasm_throwany(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf2f0);
    Some("THROWANY".to_string())
}
fn disasm_throwargany(_slice: &mut SliceData) -> Option<String> { println!("throwargany"); None }
fn disasm_throwanyif(_slice: &mut SliceData) -> Option<String> { println!("throwanyif"); None }
fn disasm_throwarganyif(_slice: &mut SliceData) -> Option<String> { println!("throwarganyif"); None }
fn disasm_throwanyifnot(_slice: &mut SliceData) -> Option<String> { println!("throwanyifnot"); None }
fn disasm_throwarganyifnot(_slice: &mut SliceData) -> Option<String> { println!("throwarganyifnot"); None }
fn disasm_try(_slice: &mut SliceData) -> Option<String> { println!("try"); None }
fn disasm_tryargs(_slice: &mut SliceData) -> Option<String> { println!("tryargs"); None }
fn disasm_ldgrams(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfa00);
    Some("LDGRAMS".to_string())
}
fn disasm_ldvarint16(_slice: &mut SliceData) -> Option<String> { println!("ldvarint16"); None }
fn disasm_stgrams(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfa02);
    Some("STGRAMS".to_string())
}
fn disasm_stvarint16(_slice: &mut SliceData) -> Option<String> { println!("stvarint16"); None }
fn disasm_ldvaruint32(_slice: &mut SliceData) -> Option<String> { println!("ldvaruint32"); None }
fn disasm_ldvarint32(_slice: &mut SliceData) -> Option<String> { println!("ldvarint32"); None }
fn disasm_stvaruint32(_slice: &mut SliceData) -> Option<String> { println!("stvaruint32"); None }
fn disasm_stvarint32(_slice: &mut SliceData) -> Option<String> { println!("stvarint32"); None }
fn disasm_ldmsgaddr<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc & 0xfffe == 0xfa40);
    Some(format!("LDMSGADDR{}", T::suffix()).to_string())
}
fn disasm_parsemsgaddr<T>(slice: &mut SliceData) -> Option<String>
where T : OperationBehavior {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc & 0xfffe == 0xfa42);
    Some(format!("PARSEMSGADDR{}", T::suffix()).to_string())
}
fn disasm_rewrite_std_addr<T>(_slice: &mut SliceData) -> Option<String> { println!("rewrite_std_addr"); None }
fn disasm_rewrite_var_addr<T>(_slice: &mut SliceData) -> Option<String> { println!("rewrite_var_addr"); None }
fn disasm_sendrawmsg(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfb00);
    Some("SENDRAWMSG".to_string())
}
fn disasm_rawreserve(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfb02);
    Some("RAWRESERVE".to_string())
}
fn disasm_rawreservex(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfb03);
    Some("RAWRESERVEX".to_string())
}
fn disasm_setcode(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfb04);
    Some("SETCODE".to_string())
}
fn disasm_setlibcode(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfb06);
    Some("SETLIBCODE".to_string())
}
fn disasm_changelib(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xfb07);
    Some("CHANGELIB".to_string())
}
fn disasm_stdict(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf400);
    Some("STDICT".to_string())
}
fn disasm_skipdict(_slice: &mut SliceData) -> Option<String> { println!("skipdict"); None }
fn disasm_lddicts(_slice: &mut SliceData) -> Option<String> { println!("lddicts"); None }
fn disasm_plddicts(_slice: &mut SliceData) -> Option<String> { println!("plddicts"); None }
fn disasm_lddict(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf404);
    Some("LDDICT".to_string())
}
fn disasm_plddict(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf405);
    Some("PLDDICT".to_string())
}
fn disasm_lddictq(_slice: &mut SliceData) -> Option<String> { println!("lddictq"); None }
fn disasm_plddictq(_slice: &mut SliceData) -> Option<String> { println!("plddictq"); None }
fn disasm_dictget(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf40a);
    Some("DICTGET".to_string())
}
fn disasm_dictgetref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf40b);
    Some("DICTGETREF".to_string())
}
fn disasm_dictiget(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf40c);
    Some("DICTIGET".to_string())
}
fn disasm_dictigetref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf40d);
    Some("DICTIGETREF".to_string())
}
fn disasm_dictuget(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf40e);
    Some("DICTUGET".to_string())
}
fn disasm_dictugetref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf40f);
    Some("DICTUGETREF".to_string())
}
fn disasm_dictset(_slice: &mut SliceData) -> Option<String> { println!("dictset"); None }
fn disasm_dictsetref(_slice: &mut SliceData) -> Option<String> { println!("dictsetref"); None }
fn disasm_dictiset(_slice: &mut SliceData) -> Option<String> { println!("dictiset"); None }
fn disasm_dictisetref(_slice: &mut SliceData) -> Option<String> { println!("dictisetref"); None }
fn disasm_dictuset(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf416);
    Some("DICTUSET".to_string())
}
fn disasm_dictusetref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf417);
    Some("DICTUSETREF".to_string())
}
fn disasm_dictsetget(_slice: &mut SliceData) -> Option<String> { println!("dictsetget"); None }
fn disasm_dictsetgetref(_slice: &mut SliceData) -> Option<String> { println!("dictsetgetref"); None }
fn disasm_dictisetget(_slice: &mut SliceData) -> Option<String> { println!("dictisetget"); None }
fn disasm_dictisetgetref(_slice: &mut SliceData) -> Option<String> { println!("dictisetgetref"); None }
fn disasm_dictusetget(_slice: &mut SliceData) -> Option<String> { println!("dictusetget"); None }
fn disasm_dictusetgetref(_slice: &mut SliceData) -> Option<String> { println!("dictusetgetref"); None }
fn disasm_dictreplace(_slice: &mut SliceData) -> Option<String> { println!("dictreplace"); None }
fn disasm_dictreplaceref(_slice: &mut SliceData) -> Option<String> { println!("dictreplaceref"); None }
fn disasm_dictireplace(_slice: &mut SliceData) -> Option<String> { println!("dictireplace"); None }
fn disasm_dictireplaceref(_slice: &mut SliceData) -> Option<String> { println!("dictireplaceref"); None }
fn disasm_dictureplace(_slice: &mut SliceData) -> Option<String> { println!("dictureplace"); None }
fn disasm_dictureplaceref(_slice: &mut SliceData) -> Option<String> { println!("dictureplaceref"); None }
fn disasm_dictreplaceget(_slice: &mut SliceData) -> Option<String> { println!("dictreplaceget"); None }
fn disasm_dictreplacegetref(_slice: &mut SliceData) -> Option<String> { println!("dictreplacegetref"); None }
fn disasm_dictireplaceget(_slice: &mut SliceData) -> Option<String> { println!("dictireplaceget"); None }
fn disasm_dictireplacegetref(_slice: &mut SliceData) -> Option<String> { println!("dictireplacegetref"); None }
fn disasm_dictureplaceget(_slice: &mut SliceData) -> Option<String> { println!("dictureplaceget"); None }
fn disasm_dictureplacegetref(_slice: &mut SliceData) -> Option<String> { println!("dictureplacegetref"); None }
fn disasm_dictadd(_slice: &mut SliceData) -> Option<String> { println!("dictadd"); None }
fn disasm_dictaddref(_slice: &mut SliceData) -> Option<String> { println!("dictaddref"); None }
fn disasm_dictiadd(_slice: &mut SliceData) -> Option<String> { println!("dictiadd"); None }
fn disasm_dictiaddref(_slice: &mut SliceData) -> Option<String> { println!("dictiaddref"); None }
fn disasm_dictuadd(_slice: &mut SliceData) -> Option<String> { println!("dictuadd"); None }
fn disasm_dictuaddref(_slice: &mut SliceData) -> Option<String> { println!("dictuaddref"); None }
fn disasm_dictaddget(_slice: &mut SliceData) -> Option<String> { println!("dictaddget"); None }
fn disasm_dictaddgetref(_slice: &mut SliceData) -> Option<String> { println!("dictaddgetref"); None }
fn disasm_dictiaddget(_slice: &mut SliceData) -> Option<String> { println!("dictiaddget"); None }
fn disasm_dictiaddgetref(_slice: &mut SliceData) -> Option<String> { println!("dictiaddgetref"); None }
fn disasm_dictuaddget(_slice: &mut SliceData) -> Option<String> { println!("dictuaddget"); None }
fn disasm_dictuaddgetref(_slice: &mut SliceData) -> Option<String> { println!("dictuaddgetref"); None }
fn disasm_dictsetb(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf441);
    Some("DICTSETB".to_string())
}
fn disasm_dictisetb(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf442);
    Some("DICTISETB".to_string())
}
fn disasm_dictusetb(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf443);
    Some("DICTUSETB".to_string())
}
fn disasm_dictsetgetb(_slice: &mut SliceData) -> Option<String> { println!("dictsetgetb"); None }
fn disasm_dictisetgetb(_slice: &mut SliceData) -> Option<String> { println!("dictisetgetb"); None }
fn disasm_dictusetgetb(_slice: &mut SliceData) -> Option<String> { println!("dictusetgetb"); None }
fn disasm_dictreplaceb(_slice: &mut SliceData) -> Option<String> { println!("dictreplaceb"); None }
fn disasm_dictireplaceb(_slice: &mut SliceData) -> Option<String> { println!("dictireplaceb"); None }
fn disasm_dictureplaceb(_slice: &mut SliceData) -> Option<String> { println!("dictureplaceb"); None }
fn disasm_dictreplacegetb(_slice: &mut SliceData) -> Option<String> { println!("dictreplacegetb"); None }
fn disasm_dictireplacegetb(_slice: &mut SliceData) -> Option<String> { println!("dictireplacegetb"); None }
fn disasm_dictureplacegetb(_slice: &mut SliceData) -> Option<String> { println!("dictureplacegetb"); None }
fn disasm_dictaddb(_slice: &mut SliceData) -> Option<String> { println!("dictaddb"); None }
fn disasm_dictiaddb(_slice: &mut SliceData) -> Option<String> { println!("dictiaddb"); None }
fn disasm_dictuaddb(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf453);
    Some("DICTUADDB".to_string())
}
fn disasm_dictaddgetb(_slice: &mut SliceData) -> Option<String> { println!("dictaddgetb"); None }
fn disasm_dictiaddgetb(_slice: &mut SliceData) -> Option<String> { println!("dictiaddgetb"); None }
fn disasm_dictuaddgetb(_slice: &mut SliceData) -> Option<String> { println!("dictuaddgetb"); None }
fn disasm_dictdel(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf459);
    Some("DICTDEL".to_string())
}
fn disasm_dictidel(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf45a);
    Some("DICTIDEL".to_string())
}
fn disasm_dictudel(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf45b);
    Some("DICTUDEL".to_string())
}
fn disasm_dictdelget(_slice: &mut SliceData) -> Option<String> { println!("dictdelget"); None }
fn disasm_dictdelgetref(_slice: &mut SliceData) -> Option<String> { println!("dictdelgetref"); None }
fn disasm_dictidelget(_slice: &mut SliceData) -> Option<String> { println!("dictidelget"); None }
fn disasm_dictidelgetref(_slice: &mut SliceData) -> Option<String> { println!("dictidelgetref"); None }
fn disasm_dictudelget(_slice: &mut SliceData) -> Option<String> { println!("dictudelget"); None }
fn disasm_dictudelgetref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf467);
    Some("DICTUDELGETREF".to_string())
}
fn disasm_dictgetoptref(_slice: &mut SliceData) -> Option<String> { println!("dictgetoptref"); None }
fn disasm_dictigetoptref(_slice: &mut SliceData) -> Option<String> { println!("dictigetoptref"); None }
fn disasm_dictugetoptref(_slice: &mut SliceData) -> Option<String> { println!("dictugetoptref"); None }
fn disasm_dictsetgetoptref(_slice: &mut SliceData) -> Option<String> { println!("dictsetgetoptref"); None }
fn disasm_dictisetgetoptref(_slice: &mut SliceData) -> Option<String> { println!("dictisetgetoptref"); None }
fn disasm_dictusetgetoptref(_slice: &mut SliceData) -> Option<String> { println!("dictusetgetoptref"); None }
fn disasm_pfxdictset(_slice: &mut SliceData) -> Option<String> { println!("pfxdictset"); None }
fn disasm_pfxdictreplace(_slice: &mut SliceData) -> Option<String> { println!("pfxdictreplace"); None }
fn disasm_pfxdictadd(_slice: &mut SliceData) -> Option<String> { println!("pfxdictadd"); None }
fn disasm_pfxdictdel(_slice: &mut SliceData) -> Option<String> { println!("pfxdictdel"); None }
fn disasm_dictgetnext(_slice: &mut SliceData) -> Option<String> { println!("dictgetnext"); None }
fn disasm_dictgetnexteq(_slice: &mut SliceData) -> Option<String> { println!("dictgetnexteq"); None }
fn disasm_dictgetprev(_slice: &mut SliceData) -> Option<String> { println!("dictgetprev"); None }
fn disasm_dictgetpreveq(_slice: &mut SliceData) -> Option<String> { println!("dictgetpreveq"); None }
fn disasm_dictigetnext(_slice: &mut SliceData) -> Option<String> { println!("dictigetnext"); None }
fn disasm_dictigetnexteq(_slice: &mut SliceData) -> Option<String> { println!("dictigetnexteq"); None }
fn disasm_dictigetprev(_slice: &mut SliceData) -> Option<String> { println!("dictigetprev"); None }
fn disasm_dictigetpreveq(_slice: &mut SliceData) -> Option<String> { println!("dictigetpreveq"); None }
fn disasm_dictugetnext(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf47c);
    Some("DICTUGETNEXT".to_string())
}
fn disasm_dictugetnexteq(_slice: &mut SliceData) -> Option<String> { println!("dictugetnexteq"); None }
fn disasm_dictugetprev(_slice: &mut SliceData) -> Option<String> { println!("dictugetprev"); None }
fn disasm_dictugetpreveq(_slice: &mut SliceData) -> Option<String> { println!("dictugetpreveq"); None }
fn disasm_dictmin(_slice: &mut SliceData) -> Option<String> { println!("dictmin"); None }
fn disasm_dictminref(_slice: &mut SliceData) -> Option<String> { println!("dictminref"); None }
fn disasm_dictimin(_slice: &mut SliceData) -> Option<String> { println!("dictimin"); None }
fn disasm_dictiminref(_slice: &mut SliceData) -> Option<String> { println!("dictiminref"); None }
fn disasm_dictumin(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf486);
    Some("DICTUMIN".to_string())
}
fn disasm_dictuminref(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf487);
    Some("DICTUMINREF".to_string())
}
fn disasm_dictmax(_slice: &mut SliceData) -> Option<String> { println!("dictmax"); None }
fn disasm_dictmaxref(_slice: &mut SliceData) -> Option<String> { println!("dictmaxref"); None }
fn disasm_dictimax(_slice: &mut SliceData) -> Option<String> { println!("dictimax"); None }
fn disasm_dictimaxref(_slice: &mut SliceData) -> Option<String> { println!("dictimaxref"); None }
fn disasm_dictumax(_slice: &mut SliceData) -> Option<String> { println!("dictumax"); None }
fn disasm_dictumaxref(_slice: &mut SliceData) -> Option<String> { println!("dictumaxref"); None }
fn disasm_dictremmin(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf492);
    Some("DICTREMMIN".to_string())
}
fn disasm_dictremminref(_slice: &mut SliceData) -> Option<String> { println!("dictremminref"); None }
fn disasm_dictiremmin(_slice: &mut SliceData) -> Option<String> { println!("dictiremmin"); None }
fn disasm_dictiremminref(_slice: &mut SliceData) -> Option<String> { println!("dictiremminref"); None }
fn disasm_dicturemmin(_slice: &mut SliceData) -> Option<String> { println!("dicturemmin"); None }
fn disasm_dicturemminref(_slice: &mut SliceData) -> Option<String> { println!("dicturemminref"); None }
fn disasm_dictremmax(_slice: &mut SliceData) -> Option<String> { println!("dictremmax"); None }
fn disasm_dictremmaxref(_slice: &mut SliceData) -> Option<String> { println!("dictremmaxref"); None }
fn disasm_dictiremmax(_slice: &mut SliceData) -> Option<String> { println!("dictiremmax"); None }
fn disasm_dictiremmaxref(_slice: &mut SliceData) -> Option<String> { println!("dictiremmaxref"); None }
fn disasm_dicturemmax(_slice: &mut SliceData) -> Option<String> { println!("dicturemmax"); None }
fn disasm_dicturemmaxref(_slice: &mut SliceData) -> Option<String> { println!("dicturemmaxref"); None }
fn disasm_dictigetjmp(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf4a0);
    Some("DICTIGETJMP".to_string())
}
fn disasm_dictugetjmp(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf4a1);
    Some("DICTUGETJMP".to_string())
}
fn disasm_dictigetexec(_slice: &mut SliceData) -> Option<String> { println!("dictigetexec"); None }
fn disasm_dictugetexec(_slice: &mut SliceData) -> Option<String> { println!("dictugetexec"); None }
fn disasm_dictpushconst(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(14).unwrap();
    assert!(opc << 2 == 0xf4a4);
    let n = slice.get_next_int(10).unwrap();
    Some(format!("DICTPUSHCONST {}", n).to_string())
}
fn disasm_pfxdictgetq(_slice: &mut SliceData) -> Option<String> { println!("pfxdictgetq"); None }
fn disasm_pfxdictget(_slice: &mut SliceData) -> Option<String> { println!("pfxdictget"); None }
fn disasm_pfxdictgetjmp(_slice: &mut SliceData) -> Option<String> { println!("pfxdictgetjmp"); None }
fn disasm_pfxdictgetexec(_slice: &mut SliceData) -> Option<String> { println!("pfxdictgetexec"); None }
fn disasm_pfxdictswitch(_slice: &mut SliceData) -> Option<String> { println!("pfxdictswitch"); None }
fn disasm_subdictget(_slice: &mut SliceData) -> Option<String> { println!("subdictget"); None }
fn disasm_subdictiget(_slice: &mut SliceData) -> Option<String> { println!("subdictiget"); None }
fn disasm_subdictuget(_slice: &mut SliceData) -> Option<String> { println!("subdictuget"); None }
fn disasm_subdictrpget(_slice: &mut SliceData) -> Option<String> { println!("subdictrpget"); None }
fn disasm_subdictirpget(_slice: &mut SliceData) -> Option<String> { println!("subdictirpget"); None }
fn disasm_subdicturpget(_slice: &mut SliceData) -> Option<String> { println!("subdicturpget"); None }
fn disasm_dictigetjmpz(_slice: &mut SliceData) -> Option<String> { println!("dictigetjmpz"); None }
fn disasm_dictugetjmpz(_slice: &mut SliceData) -> Option<String> { println!("dictugetjmpz"); None }
fn disasm_dictigetexecz(_slice: &mut SliceData) -> Option<String> { println!("dictigetexecz"); None }
fn disasm_dictugetexecz(_slice: &mut SliceData) -> Option<String> { println!("dictugetexecz"); None }
fn disasm_accept(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf800);
    Some("ACCEPT".to_string())
}
fn disasm_setgaslimit(_slice: &mut SliceData) -> Option<String> { println!("setgaslimit"); None }
fn disasm_buygas(_slice: &mut SliceData) -> Option<String> { println!("buygas"); None }
fn disasm_gramtogas(_slice: &mut SliceData) -> Option<String> { println!("gramtogas"); None }
fn disasm_gastogram(_slice: &mut SliceData) -> Option<String> { println!("gastogram"); None }
fn disasm_commit(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf80f);
    Some("COMMIT".to_string())
}
fn disasm_randu256(_slice: &mut SliceData) -> Option<String> { println!("randu256"); None }
fn disasm_rand(_slice: &mut SliceData) -> Option<String> { println!("rand"); None }
fn disasm_setrand(_slice: &mut SliceData) -> Option<String> { println!("setrand"); None }
fn disasm_addrand(_slice: &mut SliceData) -> Option<String> { println!("addrand"); None }
fn disasm_getparam(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0xf82);
    let i = slice.get_next_int(4).unwrap();
    Some(format!("GETPARAM {}", i).to_string())
}
fn disasm_now(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf823);
    Some("NOW".to_string())
}
fn disasm_blocklt(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf824);
    Some("BLOCKLT".to_string())
}
fn disasm_ltime(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf825);
    Some("LTIME".to_string())
}
fn disasm_randseed(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf826);
    Some("RANDSEED".to_string())
}
fn disasm_balance(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf827);
    Some("BALANCE".to_string())
}
fn disasm_my_addr(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf828);
    Some("MYADDR".to_string())
}
fn disasm_config_root(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf829);
    Some("CONFIGROOT".to_string())
}
fn disasm_config_dict(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf830);
    Some("CONFIGDICT".to_string())
}
fn disasm_config_ref_param(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf832);
    Some("CONFIGPARAM".to_string())
}
fn disasm_config_opt_param(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf833);
    Some("CONFIGOPTPARAM".to_string())
}
fn disasm_getglobvar(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf840);
    Some("GETGLOBVAR".to_string())
}
fn disasm_getglob(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(11).unwrap();
    assert!(opc << 1 == 0xf84);
    let k = slice.get_next_int(5).unwrap();
    assert!(k != 0);
    Some(format!("GETGLOB {}", k).to_string())
}
fn disasm_setglobvar(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf860);
    Some("SETGLOBVAR".to_string())
}
fn disasm_setglob(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(11).unwrap();
    assert!(opc << 1 == 0xf86);
    let k = slice.get_next_int(5).unwrap();
    assert!(k != 0);
    Some(format!("SETGLOB {}", k).to_string())
}
fn disasm_hashcu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf900);
    Some("HASHCU".to_string())
}
fn disasm_hashsu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf901);
    Some("HASHSU".to_string())
}
fn disasm_sha256u(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf902);
    Some("SHA256U".to_string())
}
fn disasm_chksignu(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf910);
    Some("CHKSIGNU".to_string())
}
fn disasm_chksigns(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(16).unwrap();
    assert!(opc == 0xf911);
    Some("CHKSIGNS".to_string())
}
fn disasm_cdatasizeq(_slice: &mut SliceData) -> Option<String> { println!("cdatasizeq"); None }
fn disasm_cdatasize(_slice: &mut SliceData) -> Option<String> { println!("cdatasize"); None }
fn disasm_sdatasizeq(_slice: &mut SliceData) -> Option<String> { println!("sdatasizeq"); None }
fn disasm_sdatasize(_slice: &mut SliceData) -> Option<String> { println!("sdatasize"); None }
fn disasm_dump_stack(_slice: &mut SliceData) -> Option<String> { println!("dump_stack"); None }
fn disasm_dump_stack_top(_slice: &mut SliceData) -> Option<String> { println!("dump_stack_top"); None }
fn disasm_dump_hex(_slice: &mut SliceData) -> Option<String> { println!("dump_hex"); None }
fn disasm_print_hex(_slice: &mut SliceData) -> Option<String> { println!("print_hex"); None }
fn disasm_dump_bin(_slice: &mut SliceData) -> Option<String> { println!("dump_bin"); None }
fn disasm_print_bin(_slice: &mut SliceData) -> Option<String> { println!("print_bin"); None }
fn disasm_dump_str(_slice: &mut SliceData) -> Option<String> { println!("dump_str"); None }
fn disasm_print_str(_slice: &mut SliceData) -> Option<String> { println!("print_str"); None }
fn disasm_debug_off(_slice: &mut SliceData) -> Option<String> { println!("debug_off"); None }
fn disasm_debug_on(_slice: &mut SliceData) -> Option<String> { println!("debug_on"); None }
fn disasm_dump_var(_slice: &mut SliceData) -> Option<String> { println!("dump_var"); None }
fn disasm_print_var(_slice: &mut SliceData) -> Option<String> { println!("print_var"); None }
fn disasm_dump_string(slice: &mut SliceData) -> Option<String> {
    let opc = slice.get_next_int(12).unwrap();
    assert!(opc == 0xfef);
    let n = slice.get_next_int(4).unwrap();
    let mode = slice.get_next_int(8).unwrap();
    match n {
        0 => {
            assert!(mode == 0x00);
            Some("LOGFLUSH".to_string())
        }
        _ => {
            if mode == 0x00 {
                let s = slice.get_next_slice(n as usize * 8).unwrap();
                Some(format!("LOGSTR {}", s.to_hex_string()).to_string())
            } else if mode == 0x01 {
                let s = slice.get_next_slice(n as usize * 8).unwrap();
                Some(format!("PRINTSTR {}", s.to_hex_string()).to_string())
            } else {
                println!("dump_string?");
                None
            }
        }
    }
}
