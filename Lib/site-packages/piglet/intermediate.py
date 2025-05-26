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

from itertools import chain
from typing import Optional
import re
import textwrap
import dataclasses

from piglet import parsers
from piglet.position import Position


@dataclasses.dataclass
class IntermediateNode:
    """
    An intermediate representation of the template structure.

    A template such as::

        <py:for each="i, x in enumerate(xs)">
            <a py:if="x.href" href="$x.href">
                link to ${x.name}
            </a>
        </py:for>

    Could be modelled as::

        ForNode(
            each="i, x in enumerate(xs)",
            children=[
                IfNode(expr='x.href',
                       children=[TextNode('<a href="'),
                                 InterpolateNode('x.href'),
                                 TextNode('">link to "),
                                 InterpolateNode('x.name'),
                                 TextNode('</a>')])])
    """
    pos: Position = Position(0, 0)
    children: list["IntermediateNode"] = dataclasses.field(default_factory=list)

    @classmethod
    def factory(cls, *args, **kwargs):
        return cls(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        return self

    def find(self, cls=object, test=lambda node: True):
        """
        Walk this node and all children, yielding matching nodes

        :param cls: Match only nodes of this class
        :param test: Match only nodes for which this predicate returns True
        """
        for parent, node, idx in walk_tree_pre(self):
            if isinstance(node, cls) and test(node):
                yield node

    @property
    def all_children(self):
        """
        Some nodes may have multiple lists of children (eg an IfNode
        has both ``children`` and ``else_``. The ``all_children``
        property should return an iterable over all child nodes for the
        purpose of tree walking
        """
        return self.children


class ContainerNode(IntermediateNode):
    """
    A generic container node
    """

    def append(self, child):
        """
        Add child to this node's list of children.
        """
        self.children.append(child)

    def extend(self, children):
        self.children.extend(children)

    def tip(self):
        """
        Find the newest tip of the tree
        """
        if not self.children:
            return self

        if isinstance(self.children[-1], ContainerNode):
            return self.children[-1].tip()

        return self.children[-1]


class RootNode(ContainerNode):
    "Container node for an entire document"

    @classmethod
    def factory(cls):
        return cls()


@dataclasses.dataclass
class TextNode(IntermediateNode):

    content: str = ""


@dataclasses.dataclass
class BlockNode(ContainerNode):
    """
    Models a py:block directive
    """
    name: str = ""


@dataclasses.dataclass
class IfNode(ContainerNode):
    """
    Models a py:if ... py:else directive
    """

    test: str = ""
    else_: Optional[IntermediateNode] = None

    @property
    def all_children(self):
        if self.else_:
            return chain(self.children, [self.else_])
        return self.children


class ElseNode(ContainerNode):
    """
    The else part of a ``py:if ... py:else`` directive.
    """


@dataclasses.dataclass
class DefNode(ContainerNode):
    """
    Models a py:def directive
    """
    function: str = ""


@dataclasses.dataclass
class ExtendsNode(ContainerNode):
    """
    Models a py:extends directive
    """
    href: str = ""
    ignore_missing: bool = False

    @classmethod
    def factory(cls, href, ignore_missing=False):
        return cls(href=href, ignore_missing=ignore_missing)


@dataclasses.dataclass
class IncludeNode(IntermediateNode):
    """
    Models a py:include directive
    """
    href: str = ""
    ignore_missing: bool = False


@dataclasses.dataclass
class ChooseNode(ContainerNode):
    """
    Models a py:choose directive.

    A choose node may have When, Otherwise and Text children.
    If :attribute:`ChooseNode.test` contains an expression, the value of that
    expression is is compared to any values contained in
    :attribute:`WhenNode.test` children. The first matching :class:`When` node
    is rendered and the others are dropped.

    If :attribute:`ChooseNode.test` is empty, each contained
    :attribute:`WhenNode.test` is evaluated as a boolean expression and the
    first truthful result is rendered.

    If no :class:`WhenNode` is rendered, any :class:`OtherwiseNode` directives
    will be rendered.
    """

    test: str = ""


@dataclasses.dataclass
class WhenNode(ContainerNode):
    """
    Models a py:when directive, and must be contained with a
    :class:`ChooseNode` directive.
    """

    test: str = ""


class OtherwiseNode(ContainerNode):
    pass


@dataclasses.dataclass
class ForNode(ContainerNode):
    """
    Models a py:for directive.

    The expression in :attribute:`ForNode.each` must be in the form
    `<target> in <iterator>`, and is used to generate a python for loop.
    """

    each: str = ""


@dataclasses.dataclass
class WithNode(ContainerNode):
    """
    Models a py:with directive.

    The expression in :attribute:`WithNode.vars` must be semicolon separated
    list of variable assignments, for example:

        WithNode(vars='x = 1; y = x * 2')

    The assigned variables will be available only within the scope of the
    directive
    """

    vars: str = ""

    def get_pairs(self):
        """
        Return the configured variables as a list of (target, expr) pairs.
        """
        if isinstance(self.vars, list):
            return self.vars

        values = parsers.semicolonseparated.ssv_parser.parseString(self.vars)
        values = [tuple(s.strip() for s in str(item).split("=", 1)) for item in values]
        return values


@dataclasses.dataclass
class InterpolateNode(IntermediateNode):
    """
    Renders a python expression interpolation
    """

    value: str = ""
    autoescape: bool = True


class NullNode(ContainerNode):
    """
    Used to account for text that should not appear in the compiled template,
    but still needs a node to keep the line numbering correct.
    """


@dataclasses.dataclass
class ImportNode(ContainerNode):
    href: str = ""
    alias: str = ""


@dataclasses.dataclass
class InlineCodeNode(ContainerNode):
    pysrc: str = ""


@dataclasses.dataclass
class FilterNode(ContainerNode):
    function: str = ""


@dataclasses.dataclass
class TranslationNode(ContainerNode):
    """
    Mark the contained text for translation
    """

    message: str = ""
    comment: Optional[str] = None
    whitespace: str = "normalize"

    def get_msgstr(self):

        if self.message:
            return self.message

        s = []
        for name, item in self.named_children():
            if name is None:
                s.append(item.content)
            else:
                s.append("${{{}}}".format(name))
        s = "".join(s)
        if self.whitespace == "normalize":
            s = re.sub("[ \t\r\n]+", " ", s).strip()
        elif self.whitespace == "trim":
            s = s.strip()
        elif self.whitespace == "dedent":
            s = textwrap.dedent(s).strip()
        return s

    def named_children(self):
        """
        Return a tuples of ('placeholder_name', imnode).
        For TextNode children, placeholder_name will be None.
        """
        dyn_index = 1
        for item in self.children:
            if isinstance(item, TextNode):
                yield (None, item)
            elif isinstance(item, TranslationPlaceholder):
                yield (item.name, item)
            elif isinstance(item, InterpolateNode):
                yield (item.value.strip(), item)
            else:
                yield ("dynamic.{}".format(dyn_index), item)
                dyn_index += 1


@dataclasses.dataclass
class TranslationPlaceholder(ContainerNode):
    name: str = ""


@dataclasses.dataclass
class Call(ContainerNode):
    """
    A python function call
    """
    function: str = ""


@dataclasses.dataclass
class CallKeyword(ContainerNode):
    """
    A keyword argument to a function :class:`Call`
    that may contain an arbitrary template snippet
    """
    name: str = ""


@dataclasses.dataclass
class Comment(ContainerNode):
    """
    A comment block that will be removed from the template output
    """


def _walk_tree(order, n, parent, pos):
    assert order in {"pre", "post"}
    if order == "pre":
        yield parent, n, pos
        children = enumerate(n.all_children)
    else:
        children = reversed(list(enumerate(n.all_children)))

    for index, sub in children:
        for item in _walk_tree(order, sub, n, index):
            yield item
    if order == "post":
        yield parent, n, pos


def walk_tree_post(n, parent=None, pos=0):
    """
    Walk the intermediate tree in a post order traversal.

    Yields tuples of (parent, node, index).

    A post order traversal is chosen so that nodes may be deleted
    or merged without affecting the subsequent traversal.
    """
    return _walk_tree("post", n, parent, pos)


def walk_tree_pre(n, parent=None, pos=0):
    """
    Walk the intermediate tree in a pre order traversal.

    Yields tuples of (parent, node, index).
    """
    return _walk_tree("pre", n, parent, pos)


walk_tree = walk_tree_pre
