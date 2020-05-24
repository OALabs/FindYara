# -*- coding: utf-8 -*-

########################################################################################
##
## All credit to David Berard (@_p0ly_) https://github.com/polymorf/findcrypt-yara
##
## This plugin is simply a copy of his excellent findcrypt-yara plugin only expanded
## use allow searching for any yara rules.
##
##  ____ __ __  __ ____   _  _  ___  ____   ___
## ||    || ||\ || || \\  \\// // \\ || \\ // \\
## ||==  || ||\\|| ||  ))  )/  ||=|| ||_// ||=||
## ||    || || \|| ||_//  //   || || || \\ || ||
##
## IDA plugin for Yara scanning... find those Yara matches!
##
## Add this this file to your IDA "plugins" directory
## Activate using ctl+alt+Y or Edit->Plugins->FindYara
##
## Author: @herrcore
##
########################################################################################

import idaapi
import idautils
import idc
import ida_kernwin
import operator
import yara
import string
import chardet

VERSION = "1.1"

try:
    class Kp_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            return idaapi.AST_DISABLE_FOR_FORM

    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1

except:
    pass

def lrange(num1, num2=None, step=1):
    op = operator.__lt__
    if num2 is None:
        num1, num2 = 0, num1
    if num2 < num1:
        if step > 0:
            num1 = num2
        op = operator.__gt__
    elif step < 0:
        num1 = num2
    while op(num1, num2):
        yield num1
        num1 += step

p_initialized = False



class YaraSearchResultChooser(idaapi.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose.CHCOL_HEX|10],
                ["Rule Name", idaapi.Choose.CHCOL_PLAIN|40],
                ["Match", idaapi.Choose.CHCOL_PLAIN|40],
                ["Type", idaapi.Choose.CHCOL_PLAIN|40],
            ],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        ida_kernwin.jumpto(self.items[n][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0]), res[1], res[2], res[3]]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0

#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class FindYara_Plugin_t(idaapi.plugin_t):
    comment = "FindYara plugin for IDA Pro (using yara framework)"
    help = "Still todo..."
    wanted_name = "FindYara"
    wanted_hotkey = "Ctrl-Alt-y"
    flags = idaapi.PLUGIN_KEEP


    def init(self):
        global p_initialized

        # register popup menu handlers
        try:
            Searcher.register(self, "FindYara")
        except:
            pass

        if p_initialized is False:
            p_initialized = True
            idaapi.register_action(idaapi.action_desc_t(
                "FindYara",
                "Find Yara rule matches!",
                self.search,
                None,
                None,
                0))
            idaapi.attach_action_to_menu("Edit/FindYara", "FindYara", idaapi.SETMENU_APP)
            ## Print a nice header
            print("=" * 80)
            print("  ____ __ __  __ ____   _  _  ___  ____   ___ ")
            print(" ||    || ||\\ || || \\\\  \\\\// // \\\\ || \\\\ // \\\\")
            print(" ||==  || ||\\\\|| ||  ))  )/  ||=|| ||_// ||=||")
            print(" ||    || || \\|| ||_//  //   || || || \\\\ || ||")
            print("\nFindYara v{0} by @herrcore".format(VERSION))
            print("* All credit to David Berard (@_p0ly_) for the code! *")
            print("* This is a slightly modified version of findcrypt-yara *")
            print("\nFindYara search shortcut key is Ctrl-Alt-y")
            print("=" * 80)

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass


    def toVirtualAddress(self, offset, segments):
        va_offset = 0
        for seg in segments:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset

    def search(self, yara_file):
        memory, offsets = self._get_memory()
        try:
            rules = yara.compile(yara_file)
        except:
            print("ERROR: Cannot compile Yara rules from %s" % yara_file)
            return
        values = self.yarasearch(memory, offsets, rules)
        c = YaraSearchResultChooser("FindYara scan results", values)
        r = c.show()

    def yarasearch(self, memory, offsets, rules):
        print(">>> Start yara search")
        values = list()
        matches = rules.match(data=memory)
        for rule_match in matches:
            name = rule_match.rule
            #print "%s => %d matches" % (name, len(match.strings))
            for match in rule_match.strings:
                #print "\t 0x%08x : %s" % (self.toVirtualAddress(string[0],offsets),repr(string[2]))

                match_type = 'binary'
                match_encoding = chardet.detect(match[2])['encoding']
                if match_encoding == 'ascii':
                	match_string = match[2].decode('ascii')
                	match_type = 'ascii string'
                if match_encoding == 'utf-16':
                	match_string = match[2].decode('utf-16')
                	match_type = 'wide string'
                if match_type == 'binary':
                	match_string = " ".join("{:02x}".format(ord(c)) for c in match_string)

                value = [
                    self.toVirtualAddress(match[0], offsets),
                    name,
                    match_string,
                    match_type
                ]
                values.append(value)
        print("<<< end yara search")
        return values

    def _get_memory(self):
        result = ""
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.get_segm_end(start)
            for ea in lrange(start, end):
                result += chr(idc.get_wide_byte(ea))
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return result, offsets

    def run(self, arg):
        yara_file = ida_kernwin.ask_file(0, "*.yara", 'Choose Yara File...')
        if yara_file == None:
            print("ERROR: You must choose a yara file to scan with")
        else:
            self.search(yara_file)


# register IDA plugin
def PLUGIN_ENTRY():
    return FindYara_Plugin_t()
