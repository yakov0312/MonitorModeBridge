/* Copyright 2021 The libwifi Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LIBWIFI_CORE_DATA_H
#define LIBWIFI_CORE_DATA_H

#include <sys/types.h>

/**
 *            Data Frame Layout
 *  ───────────────────────────────────
 */
struct libwifi_data {
    unsigned char transmitter[6];
    unsigned char receiver[6];
    unsigned char *body;
    size_t body_len;
};

#endif /* LIBWIFI_CORE_DATA_H */
