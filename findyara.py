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
## Updated for IDA 7.xx and Python 3
##
## To install:
##      Copy script into plugins directory, i.e: C:\Program Files\<ida version>\plugins
##
## To run:
##      Ctl+Alt+Y or Edit->Plugins->FindYara
##      Use the dialogue box to select your yara rule file and start scanning!
##
########################################################################################

import idaapi
import idautils
import ida_bytes
import idc
import ida_kernwin
import yara
import string

__AUTHOR__ = '@herrcore'

PLUGIN_NAME = "FindYara"
PLUGIN_HOTKEY = "Ctrl-Alt-Y"
VERSION = '3.3.0'

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
            if ctx.widget_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET


    class Searcher(Kp_Menu_Context):
        def activate(self, ctx):
            self.plugin.search()
            return 1

except:
    pass

p_initialized = False



class YaraSearchResultChooser(idaapi.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose.CHCOL_HEX|10],
                ["Rule Name", idaapi.Choose.CHCOL_PLAIN|20],
                ["Match Name", idaapi.Choose.CHCOL_PLAIN|20],
                ["Match", idaapi.Choose.CHCOL_PLAIN|40],
                ["Type", idaapi.Choose.CHCOL_PLAIN|10],
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
        res = [idc.atoa(res[0]), res[1], res[2], res[3], res[4]]
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
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
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
            print(r" ||    || ||\ || || \\  \\// // \\ || \\ // \\")
            print(r" ||==  || ||\\|| ||  ))  )/  ||=|| ||_// ||=||")
            print(r" ||    || || \|| ||_//  //   || || || \\ || ||")
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
        values = list()
        matches = rules.match(data=memory)
        for rule_match in matches['main']:
            name = rule_match["rule"]
            for match in rule_match["strings"]:
                match_string = match[2]
                match_type = 'unknown'
                if all(chr(c) in string.printable for c in match_string):
                    match_string = match_string.decode('utf-8')
                    match_type = 'ascii string'
                elif all(chr(c) in string.printable+'\x00' for c in match_string) and (b'\x00\x00' not in match_string):
                     match_string = match_string.decode('utf-16')
                     match_type = 'wide string'
                else:
                    match_string = " ".join("{:02x}".format(c) for c in match_string)
                    match_type = 'binary'

                value = [
                    self.toVirtualAddress(match[0], offsets),
                    name,
                    match[1],
                    match_string,
                    match_type
                ]
                values.append(value)
        return values


    def _get_memory(self):
        result = bytearray()
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.get_segm_attr(start, idc.SEGATTR_END)
            result += ida_bytes.get_bytes(start, end - start)
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return bytes(result), offsets


    def run(self, arg):
        yara_file = ida_kernwin.ask_file(0, "*.yara", 'Choose Yara File...')
        if yara_file == None:
            print("ERROR: You must choose a yara file to scan with")
        else:
            self.search(yara_file)


# register IDA plugin
def PLUGIN_ENTRY():
    return FindYara_Plugin_t()
