// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package runner provides a way to run image based gadgets easily.

# Usage

 1. The runner is created with NewRunner().
    If an OCI image is provided, the runner will pull the image and extract the metadata before returning the new `Runner` instance

 2. The gadget is started with Run() and runs in the background. There is no need to call this in another goroutine

 3. Use the gadget:

    - Wait for new events with Done()

    - Get events from the gadget with GetEvents()

    - Wait on the completion of the gadget with Wait()

    - Wait on the completion of the gadget and for all events to be consumed with WaitForAllEvents()

    - Stop the gadget with Close()
    It is recommended to pass a Context to NewRunner and use the context to stop the gadget instead

 4. Cleanup the resources with Close()
*/
package runner
