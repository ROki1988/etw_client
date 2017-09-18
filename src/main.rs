extern crate winapi;
extern crate widestring;

use std::mem;
use std::thread;
use std::time::Duration;
use std::ptr;
use winapi::um::errhandlingapi;
use winapi::um::eventtrace;
use widestring::WideCString;

const INVALID_PROCESSTRACE_HANDLE: eventtrace::TRACEHANDLE = -1isize as eventtrace::TRACEHANDLE;

fn main() {
    thread::spawn(move || {
        run();
    });
    loop {
        thread::sleep(Duration::new(1, 0));
    }
}

fn run() {
    let mut l: eventtrace::EVENT_TRACE_LOGFILE;
    let ws = WideCString::from_str("WDC.BE95A9B1-DE15-4B78-B923-A12AB70BE951").unwrap();
    unsafe {
        l = mem::zeroed();
        l.LoggerName = ws.into_raw();
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
            if r != winapi::shared::winerror::ERROR_SUCCESS {
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
       winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER {
        return;
    }

    let buff = vec![0u8; buff_size as usize];
    let info = buff.as_ptr() as eventtrace::PTRACE_EVENT_INFO;
    if eventtrace::TdhGetEventInformation(p_event, 0, ptr::null_mut(), info, &mut buff_size) !=
       winapi::shared::winerror::ERROR_SUCCESS {
        return;
    }

    show_event_info(p_event, info);
}

unsafe fn show_event_info(p_event: eventtrace::PEVENT_RECORD,
                          p_info: eventtrace::PTRACE_EVENT_INFO) {
    if (*p_info).EventDescriptor.Opcode != 1 {
        return;
    }

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

    for i in 0..(*p_info).TopLevelPropertyCount - 1 {
        show_property_info(p_event,
                           p_info,
                           (*p_info).EventPropertyInfoArray[i as usize],
                           None)
    }
}

unsafe fn show_property_info(p_event: eventtrace::PEVENT_RECORD,
                             p_info: eventtrace::PTRACE_EVENT_INFO,
                             property_info: eventtrace::EVENT_PROPERTY_INFO,
                             StructName: Option<WideCString>) {
    println!("offset: {:}", property_info.NameOffset);
    let name = read_wstring(p_info as *const u8, property_info.NameOffset as isize);
    println!("name: {:}", name.to_string_lossy());

}

unsafe fn read_wstring(p: *const u8, offset: isize) -> WideCString {
    WideCString::from_ptr_str(p.wrapping_offset(offset) as *const u16)
}
