extern crate winapi;
extern crate widestring;

use winapi::um::errhandlingapi;
use winapi::um::eventtrace;
use std::mem;
use widestring::WideCString;

const INVALID_PROCESSTRACE_HANDLE: eventtrace::TRACEHANDLE = -1isize as eventtrace::TRACEHANDLE;

fn main() {
    let mut l: eventtrace::EVENT_TRACE_LOGFILE;
    let ws = WideCString::from_str("WDC.BE95A9B1-DE15-4B78-B923-A12AB70BE951").unwrap();
    unsafe {
        l = mem::zeroed();
        l.LoggerName = ws.into_raw();
        l.EventTraceLogFile_u = eventtrace::EVENT_TRACE_LOGFILE_u([eventtrace::PROCESS_TRACE_MODE_REAL_TIME | eventtrace::PROCESS_TRACE_MODE_EVENT_RECORD]);
        l.EventTraceLogFile_u2 = eventtrace::EVENT_TRACE_LOGFILE_u2([process_event as u64]);
        
        let h = eventtrace::OpenTraceW(&mut l);
        if h == INVALID_PROCESSTRACE_HANDLE {
            println!("ERROR 0x{:x}", errhandlingapi::GetLastError());
        }
        else {
            println!("Success");
            eventtrace::CloseTrace(h);
        }
    }
}

extern fn process_event(p_event: eventtrace::PEVENT_RECORD) {
    
}