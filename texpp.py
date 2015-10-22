#!/usr/bin/env python


import re
import os


class Texpp:

    @staticmethod
    def init_class():
        Texpp.latex_ext_re = re.compile('\.tex$')
        Texpp.vhdl_ext_re = re.compile('\.vhdl?$')
        Texpp.latex_start_re = re.compile('^\s*\\\\begin{texpp}\s*$')
        Texpp.latex_end_re = re.compile('^\s*\\\\end{texpp}\s*$')
        Texpp.vhdl_pkg_start_re = re.compile('^\s*package\s+(\w+)\s+is\s*$')
        Texpp.vhdl_pkg_end_re = re.compile('^\s*end\s*package\s+(\w+)\s*;\s*$')
        Texpp.vhdl_comp_start_re = re.compile('^\s*component\s+(\w+)\s*$')
        Texpp.vhdl_comp_end_re = re.compile('^\s*end\s*component\s*;\s*$')
        return


    def __init__(self):
        Texpp.init_class()

        Texpp.self_ = self

        self.start_re = None
        self.end_re = None
        self.is_error = False
        self.block_str = ''
        self.in_block = False
        self.out_str = ''
        self.parsed_file_dir = None

        return


    @staticmethod
    def open_file(file_, flags = 'r'):
        try: f = open(file_, flags)
        except: f = None
        return f


    def is_block_start(self, line):
        if self.start_re.match(line): return True
        return False


    def is_block_end(self, line):
        if self.end_re.match(line): return True
        return False


    def process_block(self):
        eval(self.block_str)
        self.block_str = ''
        return


    def parse_file(self, filename):
        lang = self.ext_to_lang(filename)
        if lang == None: return False
        if lang != 'latex': return False

        self.start_re = Texpp.latex_start_re
        self.end_re = Texpp.latex_end_re

        self.parsed_file_dir = os.path.dirname(filename)
        if len(self.parsed_file_dir) == 0: self.parsed_file_dir = '.'

        f = Texpp.open_file(filename)
        if f == None: return -1
        while True:
            l = f.readline()
            if len(l) == 0: break

            if self.in_block == True:
                if self.is_block_end(l) == True:
                    self.process_block()
                    self.in_block = False
                else:
                    self.block_str += l
            elif self.is_block_start(l) == True:
                self.in_block = True
            else:
                self.out_str += l

        return 0


    def output_file(self, filename):
        print(self.out_str)
        return True


    @staticmethod
    def ext_to_lang(x):
        if Texpp.latex_ext_re.search(x) != None: return 'latex'
        elif Texpp.vhdl_ext_re.search(x) != None: return 'vhdl'
        return None


    @staticmethod
    def latex_escape(s):
        return (
            s.replace('_', '\\_').
            replace("\t", "\\t").
            replace("\b", "\\b").
            replace("\n", "\\\\\n")
            )


    @staticmethod
    def latex_format_error(e):
        return Texpp.latex_escape(
            '\textbf{error}: ' + e +
            '\n'
            )


    @staticmethod
    def latex_format_code(s):
        return (
            Texpp.latex_escape('\begin{vhdl}') + '\n' +
            s +
            Texpp.latex_escape('\end{vhdl}') + '\n'
            )


    @staticmethod
    def latex_format_interface(i):
        if i['err'] != None: return Texpp.latex_format_error(i['err'])
        s = Texpp.latex_escape(
            '\subsection{' + i['ns'] + '.' + i['name'] + '}'
            )
        s += '\n'
        s += Texpp.latex_escape('extracted from file ' + i['file'])
        s += '\n'
        s += Texpp.latex_format_code(i['lines'])
        s += '\n'
        return s


    @staticmethod
    def latex_format_example(e):
        if e['err'] != None: return Texpp.latex_format_error(e['err'])
        s = Texpp.latex_escape(
            '\subsection{' + e['name'] + '}'
            )
        s += Texpp.latex_escape('refer to file ' + e['file'])
        s += '\n'
        return s


    @staticmethod
    def vhdl_extract_interface(file_, name):
        i = {}
        i['lang'] = 'vhdl'
        i['ns'] = ''
        i['name'] = name
        i['file'] = file_.name
        i['generics'] = []
        i['ports'] = []
        i['notes'] = []
        i['lines'] = ''
        i['err'] = 'not found (invalid syntax ...)'

        in_pkg = False
        in_comp = False

        while True:
            l = file_.readline()
            if len(l) == 0: break

            if in_pkg == False:
                m = Texpp.vhdl_pkg_start_re.search(l)
                if (m == None) or (m.groups == 1): continue
                in_pkg = True
                i['ns'] = m.group(1)
            elif in_comp == False:
                m = Texpp.vhdl_comp_start_re.search(l)
                if (m == None) or (m.groups == 1): continue
                if m.group(1) != name: continue
                in_comp = True
                i['name'] = m.group(1)
                i['lines'] += l
            elif (in_pkg == True) and (in_comp == True):
                i['lines'] += l
                m = Texpp.vhdl_comp_end_re.search(l)
                if (m == None): continue
                i['err'] = None
                break

        return i


    @staticmethod
    def vhdl_extract_example(file_, name):
        e = {}
        e['err'] = None
        e['name'] = name
        e['file'] = file_.name
        e['notes'] = []
        return e


    def extract_(self, type_, file_, name, title):
        lang = self.ext_to_lang(file_)
        s = None
        if (lang == None) or (lang != 'vhdl'):
            s = Texpp.latex_format_error('invalid file extension: ' + file_)
        else:
            file_ = self.parsed_file_dir + '/' + file_
            f = Texpp.open_file(file_)
            if f == None:
                s = Texpp.latex_format_error('file not found: ' + file_)
            else:
                if type_ == 'interface':
                    i = Texpp.vhdl_extract_interface(f, name)
                    s = Texpp.latex_format_interface(i)
                elif type_ == 'example':
                    e = Texpp.vhdl_extract_example(f, name)
                    s = Texpp.latex_format_example(e)
                else:
                    s = Texpp.latex_format_error('invalid type_: ' + type_)

        if s != None: self.out_str += s

        return 0


    @staticmethod
    def extract(type_, file_, name, title = None):
        Texpp.self_.extract_(type_, file_, name, title)


if __name__ == '__main__':
    import sys
    in_name = sys.argv[1]
    out_name = sys.argv[2]
    pp = Texpp()
    pp.parse_file(in_name)
    pp.output_file(out_name)
