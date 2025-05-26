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

from typing import Optional

import dataclasses
import pyparsing

from piglet import parsers
from piglet.exceptions import PigletParseError
from piglet.position import Position


@dataclasses.dataclass
class ParseItem:
    pos: Optional[Position] = None

    def set_pos(self, pos):
        self.pos = pos
        return pos.advance(self.source)

    @property
    def source(self):
        raise NotImplementedError()


@dataclasses.dataclass
class OpenTag(ParseItem):

    qname: Optional[str] = None

    #: Whitespace between the name and the first attribute
    space: Optional[str] = None
    attrs: dict[str, str] = dataclasses.field(default_factory=dict)
    end: str = ">"

    def __post_init__(self):
        if isinstance(self.attrs, list):
            self.attrs = dict(self.attrs)

    def set_pos(self, pos):
        cursor = pos.advance("<{}{}".format(self.qname, self.space))
        for item in self.attrs.values():
            cursor = item.set_pos(cursor)
        return super(OpenTag, self).set_pos(pos)

    @property
    def source(self):
        attrs = "".join(v.source for v in self.attrs.values())
        return "<{}{}{}{}".format(self.qname, self.space, attrs, self.end)


@dataclasses.dataclass
class Attribute(ParseItem):
    name: Optional[str] = None
    value: Optional[str] = None
    quote: Optional[str] = None
    space1: Optional[str] = None
    space2: Optional[str] = None
    space3: Optional[str] = None

    #: The start position of the attribute's value
    value_pos: Optional[Position] = None

    def set_pos(self, pos):
        if self.value is not None:
            self.value_pos = pos.advance(
                "{0.name}{0.space1}={0.space2}{0.quote}".format(self)
            )
        else:
            self.value_pos = pos.advance(
                "{0.name}{0.space1}{0.space2}{0.quote}".format(self)
            )
        return super(Attribute, self).set_pos(pos)

    @property
    def source(self):
        if self.value is not None:
            return (
                "{0.name}{0.space1}="
                "{0.space2}{0.quote}{0.value}{0.quote}{0.space3}".format(self)
            )
        else:
            return "{0.name}{0.space1}{0.space2}{0.space3}".format(self)


@dataclasses.dataclass
class CloseTag(ParseItem):
    qname: Optional[str] = None

    @property
    def source(self):
        return "</{}>".format(self.qname)


class OpenCloseTag(OpenTag):
    @property
    def source(self):
        attrs = "".join(v.source for v in self.attrs.values())
        return "<{}{}{}>".format(self.qname, self.space, attrs)


@dataclasses.dataclass
class Comment(ParseItem):
    content: Optional[str] = None

    @property
    def source(self):
        return "<!--{}-->".format(self.content)


@dataclasses.dataclass
class Text(ParseItem):
    content: Optional[str] = None
    cdata: bool = False

    @property
    def source(self):
        return self.content


@dataclasses.dataclass
class Entity(ParseItem):
    reference: Optional[str] = None

    @property
    def source(self):
        return self.reference


@dataclasses.dataclass
class PI(ParseItem):
    target: Optional[str] = None
    content: Optional[str] = None

    @property
    def source(self):
        return "<?{}{}?>".format(self.target, self.content)


@dataclasses.dataclass
class Declaration(ParseItem):
    content: Optional[str] = None

    @property
    def source(self):
        return "<!{}>".format(self.content)


@dataclasses.dataclass
class CDATA(ParseItem):
    content: Optional[str] = None

    @property
    def source(self):
        return "<![CDATA[{}]]>".format(self.content)


def parse_html(source):
    try:
        parse_result = parsers.html_template_parser.parseString(source)
    except pyparsing.ParseException as e:
        raise PigletParseError() from e
    return add_positions(list(flatten(parse_result)))


def parse_tt(source):
    try:
        parse_result = parsers.text_template_parser.parseString(source)
    except pyparsing.ParseException as e:
        raise PigletParseError() from e
    return add_positions(list(parse_result))


def flatten(parse_result):
    for item in parse_result:
        if isinstance(item, list):
            yield from item
        else:
            yield item


def add_positions(parse_result):
    """
    Add position annotations to each parsed item
    """
    cursor = Position(1, 1)
    for item in parse_result:
        cursor = item.set_pos(cursor)
    return parse_result
