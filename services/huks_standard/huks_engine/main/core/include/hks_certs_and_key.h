/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HKS_CERTS_AND_KEY
#define HKS_CERTS_AND_KEY

#include "hks_type.h"

static const uint8_t g_rootCert[] = {
    0x30, 0x82, 0x04, 0x07, 0x30, 0x82, 0x02, 0xEF, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x4A, 0xFC, 0x65, 0x4F,
    0x67, 0x13, 0x23, 0x9A, 0xE3, 0xEB, 0xB3, 0x60, 0xE6, 0x5A, 0x90, 0xEF, 0xAA, 0x5E, 0x45, 0x8B, 0x30, 0x0D, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x81, 0x92, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
    0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x07, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
    0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x14,
    0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0B, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64,
    0x31, 0x31, 0x19, 0x30, 0x17, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x0A, 0x68,
    0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x31, 0x32, 0x32,
    0x30, 0x39, 0x32, 0x31, 0x34, 0x34, 0x5A, 0x17, 0x0D, 0x33, 0x32, 0x30, 0x31, 0x32, 0x30, 0x30, 0x39, 0x32, 0x31,
    0x34, 0x34, 0x5A, 0x30, 0x81, 0x92, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E,
    0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72,
    0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77,
    0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C,
    0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x68, 0x65,
    0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0B,
    0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x31, 0x19, 0x30, 0x17, 0x06, 0x09, 0x2A, 0x86,
    0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64,
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xE7, 0x7F, 0xDC, 0x2F, 0xFB,
    0x9C, 0xA3, 0x15, 0x38, 0xD1, 0xE2, 0x21, 0x05, 0xC7, 0xBF, 0x76, 0x44, 0xEC, 0x40, 0x27, 0x74, 0xC2, 0x6C, 0x02,
    0xEF, 0xEB, 0xC9, 0x7E, 0xC4, 0x01, 0x1B, 0x60, 0xB6, 0x3C, 0x51, 0xE9, 0xF7, 0x67, 0x1F, 0x62, 0xE7, 0x98, 0xB0,
    0x9B, 0xAB, 0x89, 0xAC, 0x42, 0xB7, 0xAA, 0x15, 0x72, 0x7F, 0x78, 0xC3, 0x3C, 0x16, 0x40, 0xD9, 0x70, 0xBC, 0xB5,
    0xAD, 0x53, 0x0C, 0x6D, 0x35, 0x8B, 0xC0, 0x6C, 0x57, 0x09, 0x79, 0x97, 0xB1, 0x19, 0x5E, 0xFB, 0x6D, 0xD2, 0xDD,
    0x0C, 0x70, 0xFE, 0xC0, 0xC0, 0x76, 0x10, 0x46, 0xBD, 0xAB, 0xFA, 0x84, 0x87, 0xCF, 0x2A, 0x31, 0xF4, 0x89, 0xFE,
    0xDF, 0xDB, 0xA8, 0xD1, 0x96, 0xD4, 0x59, 0x53, 0xBC, 0x32, 0x87, 0xB0, 0xB9, 0xB2, 0xC3, 0xD1, 0x3C, 0x98, 0xBE,
    0x66, 0xA4, 0xA2, 0x5D, 0x3F, 0x9A, 0x43, 0x96, 0x6A, 0x7D, 0xCB, 0x53, 0xD0, 0x58, 0xAE, 0x36, 0xB2, 0x40, 0x79,
    0xB0, 0x7C, 0x8A, 0xFD, 0x27, 0x86, 0x86, 0x75, 0xF4, 0xEB, 0x82, 0xE5, 0x4A, 0xAD, 0x37, 0x2C, 0xFF, 0xE7, 0x95,
    0x27, 0x27, 0x0E, 0x98, 0x2D, 0xEF, 0xE6, 0x44, 0x20, 0xE2, 0xD6, 0x84, 0xD1, 0x4C, 0x49, 0xC3, 0xEB, 0x08, 0x4B,
    0x23, 0x1C, 0x55, 0xC5, 0xE0, 0x15, 0x6F, 0x2A, 0x95, 0xC0, 0xAD, 0x60, 0x8A, 0xB0, 0x32, 0xFC, 0xA2, 0xFD, 0x91,
    0x1F, 0x13, 0xF0, 0xEF, 0x1C, 0x7B, 0x6C, 0x46, 0x41, 0x8A, 0x11, 0x89, 0x24, 0xE0, 0xB0, 0x21, 0x86, 0xAB, 0x4A,
    0xA9, 0x86, 0x49, 0x2B, 0xE8, 0x41, 0xD6, 0x00, 0x04, 0x67, 0xFE, 0x8E, 0xC7, 0xCA, 0xF2, 0xA1, 0x5F, 0x50, 0xEC,
    0x7D, 0x8B, 0x76, 0x4C, 0x01, 0x0A, 0xBC, 0xE1, 0x2C, 0x56, 0x3C, 0x65, 0x49, 0x4A, 0xC9, 0xD7, 0x57, 0xAA, 0x93,
    0x72, 0x02, 0x79, 0xC7, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D,
    0x0E, 0x04, 0x16, 0x04, 0x14, 0x9A, 0x77, 0x73, 0xE5, 0x45, 0xA4, 0x69, 0x42, 0xFE, 0xBF, 0xD4, 0x88, 0xF0, 0xA8,
    0xCE, 0x81, 0xF5, 0x51, 0xC8, 0x0C, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
    0x9A, 0x77, 0x73, 0xE5, 0x45, 0xA4, 0x69, 0x42, 0xFE, 0xBF, 0xD4, 0x88, 0xF0, 0xA8, 0xCE, 0x81, 0xF5, 0x51, 0xC8,
    0x0C, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30,
    0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
    0x34, 0x1B, 0xEA, 0x9D, 0xE7, 0x6F, 0xE5, 0x89, 0xCE, 0x97, 0xAE, 0x5A, 0x5A, 0x66, 0xF0, 0x1F, 0xD6, 0x32, 0x3B,
    0xE5, 0xF6, 0x40, 0x45, 0xD0, 0x04, 0xD1, 0x13, 0x3D, 0x49, 0x7D, 0x68, 0xB9, 0x81, 0x7F, 0x02, 0x33, 0x6E, 0xF1,
    0xAB, 0x6B, 0x49, 0x03, 0xB2, 0x5F, 0x8C, 0x73, 0xD0, 0x3C, 0xFC, 0xD8, 0x27, 0xC2, 0x8A, 0x5F, 0xE9, 0x6B, 0x31,
    0x22, 0xC9, 0xA8, 0x02, 0x85, 0x27, 0xB6, 0xE3, 0xD4, 0x91, 0x5F, 0x15, 0x17, 0x50, 0x3E, 0xAF, 0xDB, 0x25, 0x6E,
    0x5E, 0x38, 0xC6, 0x25, 0xD6, 0x63, 0x3F, 0x74, 0xB8, 0x4F, 0xA8, 0x8C, 0xAB, 0x7E, 0x19, 0x83, 0x89, 0x4D, 0xC5,
    0xA3, 0xC3, 0xFD, 0xD5, 0xB9, 0x84, 0x76, 0xC8, 0x29, 0x7F, 0xCD, 0x17, 0x0C, 0xCC, 0xCE, 0x9E, 0x60, 0xB9, 0xCF,
    0xAD, 0x81, 0x32, 0xD5, 0x65, 0x12, 0x0B, 0x2E, 0xF4, 0x36, 0x56, 0x03, 0xBD, 0x13, 0xD6, 0x42, 0xDD, 0xFB, 0xC9,
    0xE5, 0xD0, 0x4A, 0x9C, 0xE1, 0xF2, 0x45, 0x1F, 0x23, 0x13, 0x56, 0xFB, 0xC1, 0x9E, 0x41, 0x9B, 0xAD, 0xF9, 0x16,
    0xAA, 0x0C, 0x23, 0x81, 0x9D, 0x27, 0xD7, 0x68, 0xA9, 0x49, 0x1E, 0xB5, 0xB5, 0xA6, 0xBB, 0x11, 0x5A, 0x37, 0x13,
    0x4E, 0x97, 0xBD, 0x28, 0x17, 0x83, 0x6A, 0x6A, 0x2F, 0x2E, 0xA2, 0x00, 0x42, 0xC7, 0xFE, 0x0F, 0xFC, 0xAF, 0x88,
    0x84, 0x65, 0xA2, 0x4F, 0x02, 0x13, 0xFD, 0xA9, 0x4B, 0xB6, 0x31, 0xC5, 0xFA, 0x41, 0xD3, 0x4B, 0xA6, 0xB0, 0xE3,
    0x0C, 0x4A, 0xAF, 0xAA, 0x0B, 0x8F, 0xC5, 0x34, 0x9C, 0x77, 0xC1, 0x35, 0x65, 0x03, 0x2D, 0x2B, 0x0C, 0x4B, 0xDD,
    0x69, 0xC6, 0xE4, 0x97, 0xF8, 0x2D, 0x49, 0x3A, 0xDD, 0x26, 0xB7, 0x09, 0xD3, 0x3D, 0xEE, 0xC5, 0x09, 0x21, 0xCD,
    0x73, 0x41, 0x05, 0xC1, 0xF1, 0xDB, 0x8E, 0x3A, 0x7F,
};

static const uint8_t g_caCert[] = {
    0x30, 0x82, 0x03, 0xDF, 0x30, 0x82, 0x02, 0xC7, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0D, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x81, 0x92, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C,
    0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
    0x07, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
    0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x14,
    0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0B, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64,
    0x31, 0x31, 0x19, 0x30, 0x17, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x0A, 0x68,
    0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x31, 0x32, 0x32,
    0x30, 0x39, 0x32, 0x33, 0x34, 0x38, 0x5A, 0x17, 0x0D, 0x33, 0x32, 0x30, 0x31, 0x32, 0x30, 0x30, 0x39, 0x32, 0x33,
    0x34, 0x38, 0x5A, 0x30, 0x7E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C,
    0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F,
    0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
    0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C, 0x68, 0x65, 0x6C,
    0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x31, 0x31, 0x19, 0x30, 0x17, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x30, 0x82,
    0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82,
    0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xB4, 0xC9, 0x17, 0xE4, 0x80, 0x87, 0xF7,
    0x1C, 0x99, 0xCC, 0x45, 0xFA, 0x57, 0xB4, 0x9B, 0xC5, 0xB1, 0xEC, 0xDF, 0x64, 0x72, 0x53, 0x18, 0xA1, 0x45, 0x46,
    0xC8, 0x93, 0x8F, 0x0E, 0xFD, 0x0B, 0xF6, 0x41, 0x3F, 0xD6, 0x18, 0x3D, 0x1C, 0x46, 0xAF, 0x08, 0x15, 0x9A, 0x97,
    0xD6, 0x4A, 0xEB, 0xDA, 0xFE, 0x8B, 0x56, 0x22, 0x1F, 0x5F, 0x18, 0xD0, 0x5E, 0x68, 0x02, 0xEA, 0x8F, 0xD2, 0xD7,
    0x9E, 0x74, 0x30, 0x72, 0x3E, 0x28, 0xBC, 0x21, 0xA0, 0xEA, 0xB8, 0x92, 0x99, 0xD6, 0x19, 0x4C, 0x8B, 0x5D, 0xEF,
    0x3D, 0x8D, 0x5C, 0x81, 0x47, 0x06, 0xEF, 0xB7, 0x0A, 0xCC, 0x2E, 0x53, 0x32, 0x59, 0x8D, 0x4C, 0xB7, 0xAC, 0xD1,
    0xD7, 0x67, 0xF7, 0xF9, 0x58, 0xE1, 0xA8, 0xE5, 0xE2, 0x48, 0x14, 0xAF, 0x76, 0xC2, 0x11, 0x79, 0x69, 0xE2, 0xE8,
    0x41, 0x40, 0xF6, 0x25, 0x9E, 0xDB, 0xA3, 0x72, 0xD7, 0x23, 0x98, 0x47, 0x4C, 0xB5, 0xC2, 0x50, 0x9A, 0x11, 0xE9,
    0xAF, 0x62, 0x6C, 0xF5, 0xCA, 0xB6, 0x91, 0x99, 0xDE, 0xCB, 0x9F, 0x5A, 0x7B, 0x99, 0x24, 0x2C, 0x2C, 0xE9, 0x16,
    0xAA, 0x63, 0xED, 0xCB, 0xA7, 0xCF, 0x94, 0x6C, 0xDD, 0x16, 0x6C, 0xD7, 0xE3, 0x63, 0xC3, 0x9A, 0x00, 0x05, 0x2D,
    0x7C, 0xA8, 0x0C, 0xB5, 0x08, 0x40, 0x67, 0x79, 0xC2, 0xCE, 0x8B, 0xA9, 0x48, 0x3E, 0xF2, 0x1C, 0x92, 0x78, 0x01,
    0x1D, 0xDB, 0xB0, 0x73, 0x33, 0x8C, 0xE5, 0x80, 0x41, 0x5D, 0xEA, 0x8E, 0x78, 0xD9, 0x3B, 0x15, 0x64, 0xE2, 0x21,
    0xFE, 0x4C, 0xB9, 0x79, 0x6A, 0x39, 0x29, 0x59, 0xE7, 0xB5, 0xA9, 0xF1, 0x2A, 0x9F, 0x0F, 0x3C, 0x12, 0xE3, 0xD6,
    0xB0, 0xC0, 0x8F, 0x5D, 0xBC, 0x6A, 0x63, 0x83, 0x21, 0xA1, 0xDD, 0x94, 0x00, 0xE5, 0x35, 0xD7, 0x18, 0x62, 0x2C,
    0x9F, 0x97, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04,
    0x16, 0x04, 0x14, 0x4D, 0x60, 0x01, 0x09, 0x97, 0x0C, 0x4F, 0x3A, 0x3E, 0x45, 0x07, 0xB3, 0x38, 0x99, 0x3B, 0x0C,
    0xA6, 0x89, 0x11, 0x2F, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x9A, 0x77,
    0x73, 0xE5, 0x45, 0xA4, 0x69, 0x42, 0xFE, 0xBF, 0xD4, 0x88, 0xF0, 0xA8, 0xCE, 0x81, 0xF5, 0x51, 0xC8, 0x0C, 0x30,
    0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0D, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x0A, 0xCB,
    0x6D, 0x66, 0x56, 0x1B, 0x77, 0x07, 0xB8, 0x29, 0xCC, 0x04, 0x6A, 0x36, 0xF0, 0x5D, 0x0A, 0x54, 0xA7, 0x2D, 0xC6,
    0x32, 0xD5, 0x38, 0x2C, 0xC3, 0x84, 0xA9, 0xC7, 0x22, 0xEB, 0x0B, 0x56, 0xA4, 0xE7, 0x67, 0xB0, 0x07, 0x79, 0x45,
    0x39, 0xE8, 0xDC, 0xA8, 0x45, 0xF4, 0x91, 0x48, 0x81, 0x09, 0xD9, 0x33, 0x57, 0x90, 0x73, 0xBC, 0x33, 0x2C, 0x4D,
    0x37, 0x79, 0x4F, 0xE1, 0x16, 0xA9, 0x41, 0xAB, 0xCE, 0xBC, 0x43, 0x4B, 0x13, 0xDF, 0x6C, 0xDB, 0xAF, 0x48, 0xB2,
    0xE2, 0xCF, 0x0A, 0x9D, 0xE4, 0xEB, 0x39, 0xC9, 0x5F, 0x56, 0x56, 0xEC, 0xC2, 0x2B, 0x4A, 0x9E, 0xC1, 0xCF, 0xEE,
    0xAB, 0x05, 0x3B, 0xA1, 0xD8, 0x7F, 0x3B, 0xE0, 0x7F, 0xC1, 0x72, 0xF3, 0xD7, 0x68, 0x26, 0x41, 0xE1, 0x7D, 0xCD,
    0xA6, 0x37, 0xEE, 0xE2, 0xD4, 0x5C, 0x28, 0x4B, 0x52, 0x24, 0xA7, 0x55, 0x98, 0x89, 0x68, 0xB6, 0x35, 0xF5, 0xA8,
    0xCE, 0x5E, 0x60, 0x76, 0x39, 0x04, 0x34, 0x91, 0xD0, 0xCB, 0xD1, 0x62, 0xF4, 0xA5, 0x1F, 0xBF, 0xF0, 0x03, 0xD1,
    0x44, 0x18, 0x9F, 0x06, 0x1C, 0x8E, 0xEF, 0x68, 0x7C, 0x48, 0x33, 0x17, 0xF8, 0xF8, 0xE3, 0xB3, 0xF8, 0x4E, 0x30,
    0xA8, 0xA2, 0x19, 0x65, 0xF6, 0x1E, 0x54, 0x17, 0x44, 0xA5, 0x9B, 0xDF, 0x54, 0x61, 0xD1, 0x6D, 0x2E, 0x5D, 0x12,
    0x87, 0xEA, 0x73, 0x83, 0x6D, 0x86, 0x53, 0x9B, 0x4D, 0x69, 0x70, 0x00, 0x88, 0x45, 0x81, 0x3C, 0xCB, 0xAB, 0x2F,
    0x32, 0xD9, 0x8D, 0xA3, 0x0D, 0x67, 0x09, 0x93, 0xDD, 0x7F, 0xCB, 0xDB, 0xBC, 0x17, 0x58, 0xD0, 0x02, 0xEA, 0x1E,
    0x98, 0x30, 0x98, 0xE4, 0x16, 0xA5, 0x67, 0xE0, 0x67, 0xD1, 0xE6, 0x50, 0x40, 0x79, 0x57, 0xBA, 0x3C, 0x32, 0x65,
    0xFA, 0x08, 0x2B, 0xEA, 0x02, 0xB9, 0x4A,
};

static const uint8_t g_deviceCert[] = {
    0x30, 0x82, 0x03, 0xCB, 0x30, 0x82, 0x02, 0xB3, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03, 0x30, 0x0D, 0x06,
    0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x7E, 0x31, 0x0B, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A,
    0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A,
    0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x0B, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x15, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x31, 0x31,
    0x19, 0x30, 0x17, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x0A, 0x68, 0x65, 0x6C,
    0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x32, 0x30, 0x31, 0x32, 0x32, 0x30, 0x39,
    0x32, 0x35, 0x33, 0x33, 0x5A, 0x17, 0x0D, 0x33, 0x32, 0x30, 0x31, 0x32, 0x30, 0x30, 0x39, 0x32, 0x35, 0x33, 0x33,
    0x5A, 0x30, 0x7F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x13, 0x30,
    0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C,
    0x64, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F,
    0x72, 0x6C, 0x64, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0D, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
    0x77, 0x6F, 0x72, 0x6C, 0x64, 0x31, 0x31, 0x31, 0x31, 0x19, 0x30, 0x17, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
    0x0D, 0x01, 0x09, 0x01, 0x16, 0x0A, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x30, 0x82, 0x01,
    0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
    0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xBC, 0x1C, 0x78, 0x55, 0x11, 0xB6, 0x37, 0xBA,
    0xEA, 0xE2, 0x5B, 0x7C, 0x00, 0x70, 0x03, 0x05, 0xC0, 0x85, 0x1D, 0xF9, 0x52, 0x26, 0x01, 0x42, 0xA7, 0x58, 0x06,
    0x25, 0xB2, 0x21, 0xCB, 0x3E, 0xCD, 0xC1, 0x86, 0x91, 0xC7, 0x6F, 0xAE, 0xE4, 0x8F, 0x33, 0xF7, 0xAD, 0xC4, 0x1B,
    0x67, 0x69, 0x75, 0x2D, 0x23, 0x16, 0x8E, 0x85, 0x7C, 0x8D, 0x77, 0x24, 0x54, 0xC3, 0x85, 0xA8, 0xE9, 0x53, 0x96,
    0xB6, 0x25, 0x18, 0xCD, 0xC6, 0xF3, 0x46, 0xD5, 0x69, 0x67, 0x04, 0x83, 0x0E, 0x1C, 0xFA, 0x79, 0x12, 0x93, 0xE0,
    0x29, 0x1A, 0x63, 0x54, 0x6B, 0xAF, 0x47, 0x2B, 0x78, 0x7E, 0xE6, 0xF7, 0xF3, 0xF3, 0x57, 0xD5, 0x98, 0x92, 0xF5,
    0xCD, 0x7D, 0x15, 0x69, 0x88, 0x80, 0xFB, 0x00, 0xB3, 0xAC, 0x57, 0x35, 0xC3, 0x96, 0x86, 0x2A, 0x1B, 0x05, 0x21,
    0xC2, 0x18, 0xF0, 0x55, 0x28, 0x8B, 0x5E, 0x71, 0xAF, 0x00, 0x14, 0x45, 0x0F, 0xBF, 0x13, 0x29, 0x73, 0x78, 0x5D,
    0xF4, 0xDA, 0xA1, 0xB0, 0x90, 0x21, 0xD8, 0xCB, 0x8C, 0xD0, 0xAA, 0x7D, 0xE8, 0x86, 0x4B, 0xB6, 0xE6, 0xB3, 0xCB,
    0x50, 0xEC, 0x8E, 0xA7, 0xA8, 0x09, 0x36, 0xCF, 0xF7, 0x05, 0x58, 0x7B, 0xE9, 0xBF, 0x7F, 0xD6, 0x24, 0xF2, 0x3F,
    0xB9, 0x5D, 0x0C, 0x3E, 0xD5, 0x57, 0x85, 0x10, 0x09, 0x30, 0xE9, 0xA4, 0x5B, 0x6B, 0x0D, 0x06, 0x3F, 0x52, 0xB0,
    0x61, 0x7B, 0xDB, 0x0F, 0x9F, 0x4F, 0xBA, 0x19, 0x60, 0x5F, 0x92, 0x48, 0xF3, 0xE6, 0x7D, 0x5A, 0x18, 0x4E, 0xC9,
    0x3F, 0x6B, 0xE6, 0x07, 0x7A, 0x8C, 0x83, 0x12, 0x29, 0x12, 0x49, 0x95, 0x2D, 0x52, 0x31, 0x87, 0xA7, 0x70, 0x04,
    0xE9, 0xAD, 0xAF, 0xEB, 0x13, 0xEF, 0x12, 0x7E, 0x53, 0x39, 0x93, 0x59, 0xB6, 0xE1, 0x34, 0x60, 0xA4, 0xCD, 0x23,
    0xF1, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x53, 0x30, 0x51, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16,
    0x04, 0x14, 0x83, 0x4E, 0xAA, 0x7A, 0x40, 0xE7, 0x71, 0x93, 0xDC, 0xC5, 0xD8, 0x7F, 0xBB, 0x20, 0x63, 0x9C, 0x92,
    0xAF, 0xC0, 0xD4, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x4D, 0x60, 0x01,
    0x09, 0x97, 0x0C, 0x4F, 0x3A, 0x3E, 0x45, 0x07, 0xB3, 0x38, 0x99, 0x3B, 0x0C, 0xA6, 0x89, 0x11, 0x2F, 0x30, 0x0F,
    0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x78, 0x0A, 0x42,
    0x9B, 0x25, 0x05, 0xAE, 0x0B, 0x6A, 0x63, 0xD1, 0xC4, 0xBE, 0xCD, 0xBE, 0x2F, 0xF1, 0xF4, 0x6A, 0xF0, 0xE3, 0xE3,
    0x45, 0x53, 0xF2, 0x96, 0xA8, 0xC7, 0x5F, 0x82, 0x0C, 0xA6, 0x69, 0xE5, 0xD9, 0x53, 0x34, 0x0E, 0x43, 0x57, 0x0F,
    0x44, 0x98, 0x3C, 0x2E, 0x48, 0xC6, 0x42, 0xB8, 0x6E, 0x0B, 0x60, 0x94, 0x6D, 0x11, 0x92, 0xBE, 0x1B, 0x95, 0x87,
    0xFE, 0x3D, 0xD3, 0x5E, 0x9D, 0xB7, 0x9B, 0x59, 0x9B, 0xF0, 0xE1, 0x8D, 0xC9, 0x52, 0x84, 0x20, 0x49, 0xAB, 0x1F,
    0x74, 0x80, 0x3F, 0xAC, 0x95, 0xD9, 0xB5, 0xFD, 0xE6, 0x55, 0x43, 0x4B, 0x98, 0xF9, 0x5C, 0x45, 0x66, 0x42, 0x3A,
    0xD1, 0x89, 0x9A, 0xF9, 0x67, 0xB6, 0x9E, 0xFF, 0xA9, 0x69, 0x7B, 0x24, 0x22, 0x1A, 0x88, 0x3E, 0xF7, 0xD9, 0xB6,
    0x89, 0x53, 0x50, 0xD9, 0x72, 0x1C, 0xB7, 0x6A, 0x6D, 0x96, 0x58, 0x6A, 0x5C, 0x84, 0x11, 0x12, 0x04, 0xEB, 0x68,
    0x4A, 0xF7, 0x72, 0xC0, 0x6F, 0x93, 0xD3, 0x14, 0x10, 0x71, 0x7C, 0xD8, 0x43, 0xE9, 0x87, 0x3E, 0xCC, 0xA6, 0xDF,
    0x42, 0x42, 0xCC, 0x28, 0x6F, 0x64, 0x22, 0xB3, 0xF9, 0x02, 0x65, 0x21, 0x95, 0x09, 0xDD, 0x78, 0x28, 0x28, 0x7E,
    0xCC, 0x56, 0xF8, 0x80, 0x49, 0x71, 0x9C, 0x58, 0xB2, 0x8E, 0x05, 0x86, 0x14, 0x0E, 0xDD, 0xC9, 0xF3, 0xF3, 0xCC,
    0xB2, 0x16, 0xEC, 0xA9, 0xBF, 0xAB, 0x9B, 0xE5, 0x6A, 0x53, 0x9A, 0x21, 0x57, 0xC4, 0x6B, 0xFE, 0x74, 0x3E, 0x40,
    0xBB, 0xC4, 0x15, 0xAF, 0x2B, 0xAF, 0x3E, 0xEA, 0x63, 0xAF, 0xF6, 0x41, 0x26, 0xD4, 0xCB, 0xB4, 0x2F, 0x14, 0x2B,
    0xFB, 0x31, 0x71, 0x43, 0xD6, 0x40, 0x87, 0xF7, 0x61, 0x4B, 0x1B, 0x09, 0x26, 0x58, 0x36, 0xAF, 0x33, 0x59, 0x1D,
    0x54, 0xC5, 0xD9, 0x99, 0x5E, 0x78,
};

static const uint8_t g_deviceKey[] = {
    0x30, 0x82, 0x04, 0xA4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xBC, 0x1C, 0x78, 0x55, 0x11, 0xB6, 0x37,
    0xBA, 0xEA, 0xE2, 0x5B, 0x7C, 0x00, 0x70, 0x03, 0x05, 0xC0, 0x85, 0x1D, 0xF9, 0x52, 0x26, 0x01, 0x42, 0xA7, 0x58,
    0x06, 0x25, 0xB2, 0x21, 0xCB, 0x3E, 0xCD, 0xC1, 0x86, 0x91, 0xC7, 0x6F, 0xAE, 0xE4, 0x8F, 0x33, 0xF7, 0xAD, 0xC4,
    0x1B, 0x67, 0x69, 0x75, 0x2D, 0x23, 0x16, 0x8E, 0x85, 0x7C, 0x8D, 0x77, 0x24, 0x54, 0xC3, 0x85, 0xA8, 0xE9, 0x53,
    0x96, 0xB6, 0x25, 0x18, 0xCD, 0xC6, 0xF3, 0x46, 0xD5, 0x69, 0x67, 0x04, 0x83, 0x0E, 0x1C, 0xFA, 0x79, 0x12, 0x93,
    0xE0, 0x29, 0x1A, 0x63, 0x54, 0x6B, 0xAF, 0x47, 0x2B, 0x78, 0x7E, 0xE6, 0xF7, 0xF3, 0xF3, 0x57, 0xD5, 0x98, 0x92,
    0xF5, 0xCD, 0x7D, 0x15, 0x69, 0x88, 0x80, 0xFB, 0x00, 0xB3, 0xAC, 0x57, 0x35, 0xC3, 0x96, 0x86, 0x2A, 0x1B, 0x05,
    0x21, 0xC2, 0x18, 0xF0, 0x55, 0x28, 0x8B, 0x5E, 0x71, 0xAF, 0x00, 0x14, 0x45, 0x0F, 0xBF, 0x13, 0x29, 0x73, 0x78,
    0x5D, 0xF4, 0xDA, 0xA1, 0xB0, 0x90, 0x21, 0xD8, 0xCB, 0x8C, 0xD0, 0xAA, 0x7D, 0xE8, 0x86, 0x4B, 0xB6, 0xE6, 0xB3,
    0xCB, 0x50, 0xEC, 0x8E, 0xA7, 0xA8, 0x09, 0x36, 0xCF, 0xF7, 0x05, 0x58, 0x7B, 0xE9, 0xBF, 0x7F, 0xD6, 0x24, 0xF2,
    0x3F, 0xB9, 0x5D, 0x0C, 0x3E, 0xD5, 0x57, 0x85, 0x10, 0x09, 0x30, 0xE9, 0xA4, 0x5B, 0x6B, 0x0D, 0x06, 0x3F, 0x52,
    0xB0, 0x61, 0x7B, 0xDB, 0x0F, 0x9F, 0x4F, 0xBA, 0x19, 0x60, 0x5F, 0x92, 0x48, 0xF3, 0xE6, 0x7D, 0x5A, 0x18, 0x4E,
    0xC9, 0x3F, 0x6B, 0xE6, 0x07, 0x7A, 0x8C, 0x83, 0x12, 0x29, 0x12, 0x49, 0x95, 0x2D, 0x52, 0x31, 0x87, 0xA7, 0x70,
    0x04, 0xE9, 0xAD, 0xAF, 0xEB, 0x13, 0xEF, 0x12, 0x7E, 0x53, 0x39, 0x93, 0x59, 0xB6, 0xE1, 0x34, 0x60, 0xA4, 0xCD,
    0x23, 0xF1, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x56, 0xC5, 0xAF, 0x40, 0x56, 0x8E, 0x3E, 0x80,
    0xEB, 0x8E, 0x84, 0xF2, 0xDB, 0x64, 0xD0, 0x10, 0x1C, 0x31, 0x8B, 0x95, 0x11, 0xAE, 0xD4, 0x50, 0x01, 0xCF, 0x99,
    0xEE, 0x53, 0x90, 0x41, 0x27, 0xF4, 0x53, 0xBC, 0x16, 0x8C, 0xEF, 0xD8, 0xB6, 0x37, 0xD4, 0x9A, 0x00, 0xBF, 0x00,
    0x81, 0x20, 0x65, 0x5B, 0xEF, 0xDE, 0x9C, 0xD9, 0xB8, 0x8D, 0xAD, 0x12, 0xC6, 0x42, 0xF6, 0xE9, 0xE6, 0xCF, 0x97,
    0x2A, 0xE8, 0x4B, 0xDB, 0xC8, 0x55, 0x3A, 0x2C, 0x81, 0x95, 0x72, 0xC0, 0x5D, 0x87, 0x42, 0x87, 0x0C, 0xE9, 0xC7,
    0xB2, 0x4E, 0x28, 0xD9, 0xAD, 0x5E, 0xCA, 0x2E, 0xA4, 0x43, 0xAD, 0x99, 0x5D, 0x1F, 0xB8, 0x39, 0xA0, 0x4A, 0xD2,
    0x35, 0xFA, 0xE8, 0x20, 0xA9, 0x46, 0x0E, 0x02, 0xD1, 0xDE, 0xC2, 0xCF, 0xDB, 0x2C, 0x19, 0x31, 0x5D, 0x0B, 0x6D,
    0xFA, 0x11, 0xF4, 0xF2, 0xE3, 0x63, 0x32, 0xC3, 0xA8, 0x67, 0x11, 0x2B, 0x93, 0x36, 0xD6, 0x0B, 0xD1, 0x90, 0xEC,
    0x5D, 0x1D, 0x17, 0xD3, 0x60, 0x1F, 0x37, 0xF4, 0x99, 0xC3, 0xD0, 0x52, 0xDA, 0x47, 0x72, 0x38, 0x6E, 0x42, 0xB1,
    0xEA, 0x2D, 0x62, 0x8F, 0x3C, 0x8A, 0xA8, 0x72, 0xDA, 0x58, 0x59, 0xE7, 0xB3, 0xB5, 0xB4, 0x0E, 0x69, 0x03, 0xBE,
    0x31, 0x17, 0x57, 0x82, 0x37, 0xC8, 0xFF, 0x00, 0xAE, 0xE7, 0x0D, 0x76, 0xA8, 0x87, 0x94, 0xC3, 0x48, 0x4E, 0x5D,
    0x95, 0x44, 0xBE, 0x36, 0x48, 0x82, 0x2D, 0x2C, 0x2C, 0x6A, 0x08, 0xF3, 0xB3, 0x55, 0x33, 0x27, 0xA7, 0x18, 0x4E,
    0x46, 0x9A, 0xF6, 0xD0, 0x81, 0x58, 0x23, 0x90, 0xA6, 0x52, 0xD4, 0x56, 0x5B, 0x19, 0xDF, 0xDC, 0x0D, 0xA6, 0x17,
    0xF4, 0x1B, 0x1A, 0xEC, 0x0A, 0x45, 0x53, 0x56, 0x83, 0x12, 0x17, 0xE1, 0x32, 0xCC, 0x7B, 0x59, 0x4E, 0xAD, 0x2C,
    0xBD, 0x02, 0x81, 0x81, 0x00, 0xF7, 0x4B, 0xC8, 0x17, 0xEF, 0x56, 0x32, 0xFE, 0xBB, 0x25, 0x9B, 0x3E, 0xC3, 0x44,
    0xF6, 0xEE, 0xC1, 0xC9, 0xF7, 0x57, 0xBB, 0xA0, 0xCD, 0xF7, 0x84, 0x7F, 0x14, 0x53, 0x48, 0xAE, 0x32, 0x5C, 0xD6,
    0xF6, 0x26, 0x36, 0xD9, 0x8C, 0x51, 0xEB, 0xE0, 0xCD, 0xFE, 0x9C, 0xC9, 0xB4, 0x34, 0x0D, 0x7E, 0x38, 0xC1, 0x3B,
    0x8A, 0x3F, 0xED, 0x23, 0xF4, 0x8C, 0xC1, 0xD4, 0xCC, 0xE9, 0xF2, 0x39, 0x99, 0xE8, 0xE4, 0x1C, 0x05, 0x1E, 0x0A,
    0x2D, 0x56, 0xDE, 0x63, 0x04, 0xC6, 0x37, 0xA4, 0xAC, 0x9D, 0xB9, 0x25, 0x4A, 0x83, 0xF8, 0xF8, 0xFC, 0xF6, 0x81,
    0xC5, 0x6F, 0x36, 0xE4, 0x31, 0xB2, 0x3D, 0xAC, 0x85, 0xC1, 0x16, 0x73, 0xA8, 0x08, 0x81, 0x9D, 0xFF, 0xF3, 0x59,
    0x0D, 0x2E, 0x7E, 0x2A, 0x03, 0x00, 0xE8, 0x5B, 0x01, 0x6B, 0x09, 0x78, 0x5A, 0x78, 0x61, 0x88, 0x62, 0x8D, 0x37,
    0x02, 0x81, 0x81, 0x00, 0xC2, 0xBB, 0x69, 0xF1, 0xE9, 0x61, 0x36, 0x71, 0x39, 0x50, 0x00, 0x75, 0x93, 0x7D, 0x25,
    0x01, 0x74, 0x25, 0xC6, 0x4F, 0x00, 0x09, 0xBF, 0x42, 0x18, 0xD0, 0xA9, 0x22, 0xD4, 0xDE, 0x07, 0xF2, 0x40, 0x03,
    0x38, 0xF4, 0x60, 0x03, 0x78, 0x3D, 0x94, 0x68, 0x13, 0x16, 0x06, 0xFD, 0xF1, 0x9B, 0x11, 0x15, 0x3E, 0x99, 0xD2,
    0xB1, 0x01, 0x31, 0x40, 0xE7, 0x8A, 0x93, 0x22, 0x60, 0x4D, 0x7D, 0x0A, 0xC5, 0xD3, 0x30, 0x5F, 0x50, 0x35, 0x43,
    0x16, 0xBB, 0xAA, 0x98, 0x40, 0xA0, 0x1D, 0xFE, 0xCD, 0x1E, 0x93, 0xCA, 0x5D, 0xEC, 0x37, 0xBB, 0xCC, 0x77, 0x79,
    0x0B, 0xC6, 0x0F, 0x62, 0x5E, 0xBD, 0x9F, 0x9E, 0xB1, 0x14, 0xC9, 0x06, 0x1F, 0xDC, 0x96, 0xEC, 0x09, 0x73, 0x67,
    0x28, 0xBE, 0xF7, 0xE2, 0x0B, 0xB5, 0xD7, 0x16, 0x40, 0x62, 0xC8, 0xA0, 0x93, 0xED, 0x58, 0x3B, 0x2C, 0x17, 0x02,
    0x81, 0x80, 0x63, 0xBA, 0xFE, 0x21, 0x18, 0xF6, 0x8C, 0x6E, 0x4A, 0x8F, 0x2A, 0x02, 0xAF, 0xC1, 0x5A, 0x4C, 0x83,
    0x7E, 0xAD, 0xEF, 0x85, 0xCD, 0x9E, 0x02, 0xDA, 0x3E, 0x5D, 0xB6, 0x10, 0xB3, 0x9F, 0xBF, 0xED, 0x39, 0x2B, 0xC4,
    0x27, 0x0B, 0xFD, 0xE5, 0xC0, 0xAD, 0x92, 0xA7, 0x2C, 0x79, 0x2E, 0x1C, 0xDA, 0xF0, 0x8C, 0x8D, 0x34, 0x7D, 0xFF,
    0x66, 0xE6, 0xB2, 0xF5, 0x60, 0x9A, 0x9B, 0x26, 0x82, 0xB0, 0x5D, 0x49, 0xD1, 0x3B, 0x07, 0x18, 0x57, 0x9C, 0x96,
    0xE7, 0x1B, 0xFF, 0xCC, 0x64, 0xEE, 0xF0, 0x54, 0xC0, 0x83, 0x42, 0xA1, 0xDF, 0xD8, 0x34, 0x99, 0xB5, 0x43, 0xDA,
    0xC1, 0x40, 0x81, 0x7F, 0x79, 0xDA, 0x1F, 0x3A, 0xAC, 0xBD, 0xF1, 0x60, 0x44, 0x95, 0xFA, 0x4F, 0xC9, 0x8F, 0x1C,
    0x76, 0x58, 0xEB, 0xBE, 0xC9, 0x24, 0xD3, 0x43, 0xE8, 0x73, 0xA3, 0xE4, 0xC1, 0x99, 0xED, 0x15, 0x02, 0x81, 0x81,
    0x00, 0x82, 0x6D, 0xF5, 0x30, 0x4B, 0x19, 0x09, 0xD6, 0x1C, 0x85, 0x31, 0x49, 0x8F, 0x58, 0x2B, 0x09, 0x26, 0x3A,
    0x86, 0xF1, 0x33, 0x1D, 0x54, 0x35, 0x79, 0x59, 0x89, 0x70, 0x03, 0x14, 0x14, 0x4E, 0x76, 0x01, 0xB2, 0x8C, 0x3C,
    0x23, 0x16, 0xCE, 0x68, 0x30, 0xAD, 0x57, 0xFB, 0xA6, 0xEB, 0xC4, 0xE9, 0x54, 0x49, 0x71, 0xCE, 0x65, 0x30, 0x5F,
    0x45, 0x11, 0xD1, 0x07, 0x6B, 0xE7, 0x04, 0xFF, 0xD3, 0xCF, 0x5C, 0xFC, 0xF1, 0x5A, 0x4F, 0xD2, 0x77, 0xCF, 0x8B,
    0x1C, 0x1F, 0x6D, 0x1F, 0xAA, 0x22, 0xC9, 0x70, 0x44, 0x03, 0x54, 0xCC, 0x9F, 0xC4, 0xFB, 0xE0, 0xDF, 0xB9, 0xF1,
    0x63, 0xFA, 0x01, 0x18, 0x80, 0xBA, 0x2B, 0x29, 0xDA, 0x28, 0x4D, 0x1F, 0xE9, 0x49, 0x0B, 0x3A, 0xF5, 0x57, 0xB3,
    0xC0, 0x7C, 0x07, 0x77, 0xE1, 0x37, 0x8E, 0xF2, 0xC2, 0x5B, 0x52, 0x85, 0xDE, 0x5C, 0x51, 0x02, 0x81, 0x81, 0x00,
    0x9E, 0xB5, 0x04, 0x1F, 0x3A, 0xF2, 0x5A, 0x76, 0x0C, 0x43, 0xD7, 0x92, 0xCA, 0xF5, 0x22, 0x5E, 0x88, 0xC3, 0x69,
    0x80, 0xDC, 0x8C, 0xB0, 0xB3, 0x8C, 0x3F, 0xF6, 0x50, 0x64, 0x9E, 0xDF, 0xDD, 0x43, 0x12, 0x3A, 0xA2, 0x9F, 0x4D,
    0xE0, 0xD1, 0xE4, 0x3F, 0xE4, 0xA1, 0x2B, 0x75, 0xF4, 0x3D, 0x69, 0xA0, 0x14, 0x34, 0x8C, 0x44, 0xF8, 0xEB, 0xA4,
    0x9B, 0xF8, 0xA3, 0x67, 0x51, 0x98, 0xEB, 0xA7, 0x1C, 0xF2, 0xE9, 0xC6, 0x37, 0x12, 0x3E, 0xA8, 0xB7, 0xAE, 0x20,
    0x75, 0xB7, 0xF4, 0x63, 0xFE, 0x26, 0x71, 0x33, 0x93, 0xF0, 0x53, 0xCA, 0xC7, 0x45, 0xFD, 0xB0, 0x34, 0x4C, 0xF2,
    0x1F, 0x49, 0x0D, 0x14, 0xD1, 0x12, 0x0F, 0xAA, 0xDB, 0x7D, 0x1F, 0x1E, 0x7D, 0x65, 0x46, 0xCD, 0xCE, 0x30, 0x99,
    0x2D, 0x24, 0x49, 0x42, 0x54, 0x79, 0xCF, 0x7F, 0xDB, 0x1D, 0xA6, 0x63, 0x36, 0x0F,
};

#endif