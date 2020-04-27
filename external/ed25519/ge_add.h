// Copyright (c) 2012-2017, The CryptoNote Developers, The Bytecoin Developers
// Copyright (c) 2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#ifndef GE_ADD_H
#define GE_ADD_H

#include "fe_add.h"
#include "fe_mul.h"
#include "fe_sub.h"
#include "ge.h"

void ge_add(ge_p1p1 *, const ge_p3 *, const ge_cached *);

#endif // GE_ADD_H
