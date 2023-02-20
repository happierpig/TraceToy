#include "analyzer.h"

// #define printOut

#define panic(args...) \
{ \
    fprintf(stderr, "%sPanic on %s:%d: ", "[Log]", __FILE__, __LINE__); \
    fprintf(stderr, args); \
    fprintf(stderr, "\n"); \
    fflush(stderr); \
    /**reinterpret_cast<int*>(0L) = 42;*/ /*SIGSEGVs*/ \
    exit(-1); \
}

std::string tracePath("/home/dreamer/Desktop/Mycode/trace/13378400607429273214.462778.memtrace");
long instCount = 0, priorCount = 0;

struct InstInfo{
  uint64_t pc;                    // instruction address
  uint64_t pid;                   // process ID
  uint64_t tid;                   // thread ID
  uint64_t size;                  // Instruction Size
  bool valid;                     // false at first to deal corner case
};

struct ResultBucket{
  std::vector<int> intervalInst;
  long switchCount = 0;
  long causeBySyscall = 0;
  std::vector<int> intervalInstCausedBySyscall;
}result;

void addSwitch(const InstInfo & instInfo, long interval){
  if(instInfo.valid == false || interval == 0) return; // The first CPU marker
  result.intervalInst.push_back(interval);
  result.switchCount++;
  if(instInfo.size == 2){ // possible system call
    result.causeBySyscall++;
    result.intervalInstCausedBySyscall.push_back(interval);
  }
}

void checkResult(){
  if(result.intervalInst.size() != result.switchCount || result.intervalInstCausedBySyscall.size() != result.causeBySyscall)
    panic("[Result] Fail to match.");
}

void processInst(const memref_t & insRef, InstInfo & info){
  if(!type_is_instr(insRef.instr.type)) panic("[ProcessInst] Dismatch Trace Type");
  info.pc = insRef.instr.addr;
  info.pid = insRef.instr.pid;
  info.tid = insRef.instr.tid;
  info.size = insRef.instr.size;
  info.valid = true;
}

void printInst(const InstInfo & info){
  printf("Inst pc: %ld\tsize: %ld\tpid: %ld\ttid: %ld\n", info.pc, info.size, info.pid, info.tid);
}

void processMarker(const _memref_marker_t & markerRef, const InstInfo & instInfo){
  trace_marker_type_t tmpType = markerRef.marker_type;
  switch (tmpType){
  case TRACE_MARKER_TYPE_TIMESTAMP:
    #ifdef printOut
      printf("[Marker] Time Stamp %ld\n", (long)markerRef.marker_value);
    #endif
    break;
  case TRACE_MARKER_TYPE_SYSCALL_ID:
    panic("Get SYSCALL"); // trace didn't contain it.
    break;
  case TRACE_MARKER_TYPE_KERNEL_XFER:
    #ifdef printOut
      printf("[Marker] Kernel_Xfer.\n");
      printf("%d\n", instCount);
    #endif
    break;
  case TRACE_MARKER_TYPE_CPU_ID:
    #ifdef printOut
      printf("[Marker] CPU id is %d\n", markerRef.marker_value);
      printf("%d\n", instCount);
    #endif
    addSwitch(instInfo, instCount - priorCount);
    priorCount = instCount;
    break;
  default:
    break;
  }
}

int main(){
    analyzer_t * traceReader = new analyzer_t(tracePath);
    if (!(*traceReader)) {
      panic("Failure starting memtrace reader");
      return false;
    }
    reader_t * readerIter = &(traceReader->begin());
    reader_t * readerEnd = &(traceReader->end());
    memref_t insRef;
    InstInfo priorInfo; priorInfo.valid = false;
    while(true){
      if(*readerIter == *readerEnd) break;
      insRef = **readerIter;
      trace_type_t tmpTypr = insRef.instr.type;
      if(type_is_instr(tmpTypr)){
        ++instCount;
        processInst(insRef, priorInfo);
        #ifdef printOut
          printInst(priorInfo);
        #endif
      }else if(tmpTypr == TRACE_TYPE_MARKER){
        processMarker(insRef.marker, priorInfo);
      }
      ++(*readerIter);
      if(instCount == 100000000) break;
    }

    checkResult();
    printf("[Result] Total %ld thread switches ; %ld caused by syscall, account for %f%%\n", 
        result.switchCount, result.causeBySyscall, ((double)result.causeBySyscall / result.switchCount) * 100);
    // for(int i = 0;i < result.intervalInst.size();++i) printf("%d\n", result.intervalInst[i]);
    // for(int i = 0;i < result.intervalInstCausedBySyscall.size();++i) printf("%d\n", result.intervalInstCausedBySyscall[i]);
    return 0;
}