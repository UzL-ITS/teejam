%macro m_rdtsc 0
  lfence
  rdtsc
  shl rdx, 32
  or rax, rdx
%endmacro

%macro m_rdtsc 1
  m_rdtsc
  mov %1, rax
%endmacro

%macro m_rdtscp 0
  rdtscp
  shl rdx, 32
  or rax, rdx
%endmacro

%macro m_rdtscp 1
  m_rdtscp
  mov %1, rax
%endmacro
