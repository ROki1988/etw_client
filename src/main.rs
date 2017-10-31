extern crate winapi;
extern crate widestring;

use std::mem;
use std::thread;
use std::time::Duration;
use std::ptr;
use std::collections::HashMap;
use winapi::um::errhandlingapi;
use winapi::um::eventtrace;
use widestring::WideCString;
use winapi::shared::winerror;

const INVALID_PROCESSTRACE_HANDLE: eventtrace::TRACEHANDLE = -1isize as eventtrace::TRACEHANDLE;

fn main() {
    let s_name =
        WideCString::from_str(eventtrace::KERNEL_LOGGER_NAMEW).unwrap().into_vec_with_nul();
    let mut prop_buf =
        vec![0u8; mem::size_of::<eventtrace::EVENT_TRACE_PROPERTIES>() + s_name.len() * 2];
    let prop = prop_buf.as_mut_ptr() as eventtrace::PEVENT_TRACE_PROPERTIES;
    unsafe {
        (*prop).Wnode.BufferSize = prop_buf.len() as u32;
        (*prop).Wnode.Guid = eventtrace::SystemTraceControlGuid;
        (*prop).Wnode.ClientContext = 1;
        (*prop).Wnode.Flags = eventtrace::WNODE_FLAG_TRACED_GUID;
        (*prop).EnableFlags = eventtrace::EVENT_TRACE_FLAG_PROCESS;
        (*prop).MaximumFileSize = 1;
        (*prop).LogFileMode = eventtrace::EVENT_TRACE_REAL_TIME_MODE;
        (*prop).LoggerNameOffset = mem::size_of::<eventtrace::EVENT_TRACE_PROPERTIES>() as u32;

        let mut s_handle = 0;
        match eventtrace::StartTraceW(&mut s_handle, s_name.as_ptr(), prop) {
            winerror::ERROR_SUCCESS |
            winerror::ERROR_ALREADY_EXISTS => {
                thread::spawn(move || {
                    run();
                });
                loop {
                    thread::sleep(Duration::new(1, 0));
                }
            }
            winerror::ERROR_ACCESS_DENIED => println!("ERROR_ACCESS_DENIED"),
            x @ _ => println!("0x{:x}", x),
        }
    }

}

fn run() {
    let mut l: eventtrace::EVENT_TRACE_LOGFILE;
    unsafe {
        l = mem::zeroed();
        let s_name = WideCString::from_str(eventtrace::KERNEL_LOGGER_NAMEW).unwrap();
        l.LoggerName = s_name.into_raw();
        l.EventTraceLogFile_u =
            eventtrace::EVENT_TRACE_LOGFILE_u([eventtrace::PROCESS_TRACE_MODE_REAL_TIME |
                                               eventtrace::PROCESS_TRACE_MODE_EVENT_RECORD]);
        l.EventTraceLogFile_u2 = eventtrace::EVENT_TRACE_LOGFILE_u2([process_event as u64]);
        let mut h = eventtrace::OpenTraceW(&mut l);
        if h == INVALID_PROCESSTRACE_HANDLE {
            println!("ERROR 0x{:x}", errhandlingapi::GetLastError());
        } else {
            println!("Success: 0x{:x}", h);
            let r = eventtrace::ProcessTrace(&mut h, 1, ptr::null_mut(), ptr::null_mut());
            if r != winerror::ERROR_SUCCESS {
                println!("ERROR 0x{:x}", r);
                eventtrace::CloseTrace(h);
            }
        }
    }
}

unsafe extern "system" fn process_event(p_event: eventtrace::PEVENT_RECORD) {
    let mut buff_size = 0;

    if eventtrace::TdhGetEventInformation(p_event,
                                          0,
                                          ptr::null_mut(),
                                          ptr::null_mut(),
                                          &mut buff_size) !=
       winerror::ERROR_INSUFFICIENT_BUFFER {
        return;
    }

    let buff = vec![0u8; buff_size as usize];
    let info = buff.as_ptr() as eventtrace::PTRACE_EVENT_INFO;
    if eventtrace::TdhGetEventInformation(p_event, 0, ptr::null_mut(), info, &mut buff_size) !=
       winerror::ERROR_SUCCESS {
        return;
    }

    get_event_info(p_event, info).map(|x| println!("{:?}", x));
}

unsafe fn get_event_info(p_event: eventtrace::PEVENT_RECORD,
                         p_info: eventtrace::PTRACE_EVENT_INFO) -> Option<TdhInfo> {
    let p = p_info as *const u8;
    println!("Id: {:}.", (*p_event).EventHeader.EventDescriptor.Id);
    println!("Task: {:}.", (*p_event).EventHeader.EventDescriptor.Task);
    println!("PID: {:}.", (*p_event).EventHeader.ProcessId);
    println!("Provider: {:}.",
             read_wstring(p, (*p_info).ProviderNameOffset as isize).to_string_lossy());
    println!("Level: {:}.",
             read_wstring(p, (*p_info).LevelNameOffset as isize).to_string_lossy());
    println!("Channel: {:}.",
             read_wstring(p, (*p_info).ChannelNameOffset as isize).to_string_lossy());
    println!("Keywords: {:}.",
             read_wstring(p, (*p_info).KeywordsNameOffset as isize).to_string_lossy());
    println!("Task: {:}.",
             read_wstring(p, (*p_info).TaskNameOffset as isize).to_string_lossy());
    println!("Opcode: {:}.",
             read_wstring(p, (*p_info).OpcodeNameOffset as isize).to_string_lossy());
    println!("ActivityID: {:}.",
             read_wstring(p, (*p_info).ActivityIDNameOffset as isize).to_string_lossy());
    println!("RelatedActivityID: {:}.",
             read_wstring(p, (*p_info).RelatedActivityIDNameOffset as isize).to_string_lossy());
    println!("TopLevelPropertyCount: {:}.",
             (*p_info).TopLevelPropertyCount);

    if (*p_info).TopLevelPropertyCount <= 0 {
        return None;
    }


    let a = TdhInfo {
        property: (0..(*p_info).TopLevelPropertyCount - 1)
            .into_iter()
            .map(|i| {
                get_property_info(p_event,
                                  p_info,
                                  (*p_info).EventPropertyInfoArray[i as usize])
            })
            .collect(),
    };

    Some(a)
}

#[derive(Debug)]
struct TdhInfo {
    property: HashMap<String, TdhProperty>,
}

#[derive(Debug)]
enum TdhProperty {
    Struct(Box<HashMap<String, TdhProperty>>),
    Map(Box<HashMap<String, TdhProperty>>),
    WString(WideCString),
    Int8(i8),
    UInt8(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Float(f32),
    Double(f64),
    Bool(bool),
    Pointer32(u32),
    Pointer64(u64),
    NoImple,
}

unsafe fn get_property_map(p_event: eventtrace::PEVENT_RECORD,
                           p_info: eventtrace::PTRACE_EVENT_INFO)
                           -> HashMap<String, TdhProperty> {

    if (*p_info).TopLevelPropertyCount <= 0 {
        return HashMap::new();
    }

    (0..(*p_info).TopLevelPropertyCount - 1)
        .into_iter()
        .map(|i| {
            get_property_info(p_event,
                              p_info,
                              (*p_info).EventPropertyInfoArray[i as usize])
        })
        .collect()
}

unsafe fn get_property_info(p_event: eventtrace::PEVENT_RECORD,
                            p_info: eventtrace::PTRACE_EVENT_INFO,
                            property_info: eventtrace::EVENT_PROPERTY_INFO)
                            -> (String, TdhProperty) {
    let name = read_wstring(p_info as *const u8, property_info.NameOffset as isize);

    if property_info.Flags == eventtrace::PropertyStruct {
        let r = get_property_map(p_event, p_info);
        (name.to_string_lossy(), TdhProperty::Struct(Box::new(r)))
    } else {
        get_property_info_non_struct(p_event, p_info, property_info, None)
            .expect("!!!!!!!!!!!!")
    }
}
unsafe fn get_property_info_non_struct(p_event: eventtrace::PEVENT_RECORD,
                                       p_info: eventtrace::PTRACE_EVENT_INFO,
                                       property_info: eventtrace::EVENT_PROPERTY_INFO,
                                       struct_name: Option<&WideCString>)
                                       -> Result<(String, TdhProperty), u32> {
    use winapi::shared::ntdef::{PSHORT, PUSHORT, PLONG, PULONG, PULONGLONG, DOUBLE, PCHAR, PUCHAR, PLONGLONG};
    use winapi::shared::minwindef::{PFLOAT, PBOOL};


    let name = read_wstring(p_info as *const u8, property_info.NameOffset as isize);
    let mut a = if let Some(pat) = struct_name {
        vec![eventtrace::PROPERTY_DATA_DESCRIPTOR {
                 PropertyName: pat.as_ptr() as u64,
                 ArrayIndex: 0,
                 Reserved: 0,
             },
             eventtrace::PROPERTY_DATA_DESCRIPTOR {
                 PropertyName: name.as_ptr() as u64,
                 ArrayIndex: std::u32::MAX,
                 Reserved: 0,
             }]
    } else {
        vec![eventtrace::PROPERTY_DATA_DESCRIPTOR {
                 PropertyName: name.as_ptr() as u64,
                 ArrayIndex: std::u32::MAX,
                 Reserved: 0,
             }]
    };

    let mut buff_size = 0;

    let status = eventtrace::TdhGetPropertySize(p_event,
                                   0,
                                   ptr::null_mut(),
                                   a.len() as u32,
                                   a.as_mut_ptr(),
                                   &mut buff_size);

    if status != winerror::ERROR_SUCCESS {
        return Err(status)
    }
    let mut buff = vec![0u8; buff_size as usize];
    eventtrace::TdhGetProperty(p_event,
                               0,
                               ptr::null_mut(),
                               a.len() as u32,
                               a.as_mut_ptr(),
                               buff_size,
                               buff.as_mut_ptr());

    if property_info.EventPropertyInfo_u1.nonStructType().MapNameOffset == 0 {
        if property_info.Flags == eventtrace::PropertyStruct {
            let p: *mut eventtrace::EVENT_PROPERTY_INFO = &mut (*p_info).EventPropertyInfoArray[0];
            let a: HashMap<String, TdhProperty> = (0..property_info.EventPropertyInfo_u1.StructType().NumOfStructMembers - 1)
        .into_iter()
        .map(|i| {
            get_property_info_non_struct(p_event,
                              p_info,
                              *(p.offset(i as isize + property_info.EventPropertyInfo_u1.StructType().StructStartIndex as isize)),
                              Some(&name))
        })
        .filter_map(|x| x.ok())
        .collect();
            return Ok((name.to_string_lossy(), TdhProperty::Struct(Box::new(a))));
        }

        let contain_name = struct_name.map_or(name.to_string_lossy(), |wc| {
            format!("{:}.{:}", wc.to_string_lossy(), name.to_string_lossy())
        });

        let v = match property_info.EventPropertyInfo_u1.nonStructType().InType as u32 {
            eventtrace::TDH_INTYPE_UNICODESTRING => {
                TdhProperty::WString(WideCString::from_ptr_str(buff.as_ptr() as *const u16))
            }
            //            eventtrace::TDH_INTYPE_ANSISTRING => (),
            eventtrace::TDH_INTYPE_INT8 => TdhProperty::Int8(*(buff.as_ptr() as PCHAR)),
            eventtrace::TDH_INTYPE_UINT8 => TdhProperty::UInt8(*(buff.as_ptr() as PUCHAR)),
            eventtrace::TDH_INTYPE_INT16 => TdhProperty::Int16(*(buff.as_ptr() as PSHORT)),
            eventtrace::TDH_INTYPE_UINT16 => TdhProperty::UInt16(*(buff.as_ptr() as PUSHORT)),
            eventtrace::TDH_INTYPE_INT32 => TdhProperty::Int32(*(buff.as_ptr() as PLONG)),
            eventtrace::TDH_INTYPE_UINT32 => TdhProperty::UInt32(*(buff.as_ptr() as PULONG)),
            eventtrace::TDH_INTYPE_INT64 => TdhProperty::Int64(*(buff.as_ptr() as PLONGLONG)),
            eventtrace::TDH_INTYPE_UINT64 => TdhProperty::UInt64(*(buff.as_ptr() as PULONGLONG)),
            eventtrace::TDH_INTYPE_FLOAT => TdhProperty::Float(*(buff.as_ptr() as PFLOAT)),
            eventtrace::TDH_INTYPE_DOUBLE => TdhProperty::Double(*(buff.as_ptr() as *const DOUBLE)),
            eventtrace::TDH_INTYPE_BOOLEAN => TdhProperty::Bool(*(buff.as_ptr() as PBOOL) != 0),
            //            eventtrace::TDH_INTYPE_BINARY => (),
            //            eventtrace::TDH_INTYPE_GUID => (),
            eventtrace::TDH_INTYPE_POINTER => if (*p_event).EventHeader.Flags & 0x0020 == 0x0020 {TdhProperty::Pointer32(buff.as_ptr() as u32)} else {TdhProperty::Pointer64(buff.as_ptr() as u64)},
            //            eventtrace::TDH_INTYPE_FILETIME => (),
            //            eventtrace::TDH_INTYPE_SYSTEMTIME => (),
            //            eventtrace::TDH_INTYPE_SID => (),
            //            eventtrace::TDH_INTYPE_HEXINT32 => (),
            //            eventtrace::TDH_INTYPE_HEXINT64 => (),
            //            eventtrace::TDH_INTYPE_COUNTEDSTRING => (),
            //            eventtrace::TDH_INTYPE_COUNTEDANSISTRING => (),
            //            eventtrace::TDH_INTYPE_REVERSEDCOUNTEDSTRING => (),
            //            eventtrace::TDH_INTYPE_REVERSEDCOUNTEDANSISTRING => (),
            //            eventtrace::TDH_INTYPE_NONNULLTERMINATEDSTRING => (),
            //            eventtrace::TDH_INTYPE_NONNULLTERMINATEDANSISTRING => (),
            //            eventtrace::TDH_INTYPE_UNICODECHAR => (),
            //            eventtrace::TDH_INTYPE_ANSICHAR => (),
            //            eventtrace::TDH_INTYPE_SIZET => (),
            //            eventtrace::TDH_INTYPE_HEXDUMP => (),
            //            eventtrace::TDH_INTYPE_WBEMSID => (),
            _ => TdhProperty::NoImple,
        };
        Ok((contain_name, v))
    } else {
        let map_name = (p_info as *const u8)
            .offset(property_info.EventPropertyInfo_u1.nonStructType().MapNameOffset as isize);
        let map_value = *(buff.as_ptr() as PULONG);

        let mut map_buff_size = 0;
        let status = eventtrace::TdhGetEventMapInformation(p_event,
                                                           map_name as *mut u16,
                                                           ptr::null_mut(),
                                                           &mut map_buff_size);
        if status != winerror::ERROR_INSUFFICIENT_BUFFER {
            return Err(status);
        }

        let map_buff = vec![0u8; map_buff_size as usize];
        let map = map_buff.as_ptr() as eventtrace::PEVENT_MAP_INFO;

        let status = eventtrace::TdhGetEventMapInformation(p_event,
                                                           map_name as *mut u16,
                                                           map,
                                                           &mut map_buff_size);
        if status != winerror::ERROR_SUCCESS {
            return Err(status);
        }

        if (*map).Flag == eventtrace::EVENTMAP_INFO_FLAG_MANIFEST_VALUEMAP {
            let a: HashMap<String, TdhProperty> = (0..(*map).EntryCount - 1)
                .into_iter()
                .filter(|&x| (*map).MapEntryArray[x as usize].EventMapEntry_u.Value() == &map_value)
                .map(|i| {
                    let key_name =
                        read_wstring(map as *const u8,
                                     (*map).MapEntryArray[i as usize].OutputOffset as isize);
                    (key_name.to_string_lossy(), TdhProperty::UInt32(map_value))
                })
                .collect();

            Ok((read_wstring((p_info as *const u8),
                             property_info.EventPropertyInfo_u1
                                 .nonStructType()
                                 .MapNameOffset as isize)
                .to_string_lossy(),
                TdhProperty::Map(Box::new(a))))
        } else {
            Err(1)
        }
    }
}


unsafe fn read_wstring(p: *const u8, offset: isize) -> WideCString {
    WideCString::from_ptr_str(p.wrapping_offset(offset) as *const u16)
}
