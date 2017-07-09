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
    let event = *p_event;
    if event.EventHeader.EventDescriptor.Id == 0 {
        return;
    }

    println!("Id: {:}", (*p_event).EventHeader.EventDescriptor.Id);
    println!("Task: {:}", (*p_event).EventHeader.EventDescriptor.Task);
}