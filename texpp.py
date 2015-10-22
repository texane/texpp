#!/usr/bin/env python


import re
import os


class Texpp:

    @staticmethod
    def init_class():
        Texpp.latex_ext_re = re.compile('\.tex$')
        Texpp.vhdl_ext_re = re.compile('\.vhdl?$')
        Texpp.latex_start_re = re.compile('\\\\begin{texpp}')
        Texpp.latex_end_re = re.compile('\\\\end{texpp}')
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
        return s.replace('_', '\\_').replace("\t", "\\t").replace("\n", "\\\\")


    @staticmethod
    def latex_format_error(e):
        return Texpp.latex_escape(
            '\textbf{error}: ' + e +
            '\n'
            )


    @staticmethod
    def latex_format_interface(i):
        return Texpp.latex_escape(
            '\textbf{interface}: ' +
            i['name'] + ', ' +
            'refer to ' + i['file'] +
            '\n'
            )


    @staticmethod
    def latex_format_example(e):
        return Texpp.latex_escape(
            '\textbf{example}: ' + e['name'] + ', '
            'refer to ' + e['file'] +
            '\n'
            )


    @staticmethod
    def vhdl_extract_interface(file_, name):
        i = {}
        i['ns'] = 'work'
        i['name'] = name
        i['file'] = file_.name
        i['generics'] = []
        i['ports'] = []
        i['notes'] = []
        return i


    @staticmethod
    def vhdl_extract_example(file_, name):
        e = {}
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
