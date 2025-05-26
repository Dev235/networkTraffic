# Copyright 2016 Oliver Cope
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import dataclasses

try:
    dataclass_with_slots = dataclasses.dataclass(slots=True, frozen=True)
except TypeError:
    # Python <= 3.9
    dataclass_with_slots = dataclasses.dataclass(frozen=True)


@dataclass_with_slots
class Position:
    line: int
    char: int

    def advance(self, text):
        return self.__class__(*update_pos(self, text))


def update_pos(oldpos, s):
    """
    Update a line, char position as if the cursor has moved through text ``s``.
    """
    c = oldpos.char
    line = oldpos.line + s.count("\n")
    last_newline = s.rfind("\n")
    if last_newline < 0:
        c = c + len(s)
    else:
        c = len(s) - last_newline
    return (line, c)
