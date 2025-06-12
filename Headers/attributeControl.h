//
// Created by yakov on 6/12/25.
//

#pragma once

#if defined(__GNUC__) || defined(__clang__)
  #define HIDDEN __attribute__((visibility("hidden")))
#else
  #define HIDDEN
#endif

#if defined(__GNUC__) || defined(__clang__)
  #define CTOR __attribute__((constructor))
#else
  #define CTOR
#endif