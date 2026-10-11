// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2026 IT-EXPRESS Bayern and LunarBridge contributors.
// Compile-only CI fixture: this executable is inspected, never launched.
#import <Metal/Metal.h>
#import <IOSurface/IOSurface.h>
#import <IOKit/IOKitLib.h>

NSArray<id<MTLDevice>> *(*metal_enumeration)(void) = MTLCopyAllDevices;
IOSurfaceRef (*surface_creation)(CFDictionaryRef) = IOSurfaceCreate;
CFMutableDictionaryRef (*registry_matching)(uint64_t) = IORegistryEntryIDMatching;

int main(void) {
    return !metal_enumeration || !surface_creation || !registry_matching;
}
