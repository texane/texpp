#!/usr/bin/env python


class Texpp:
    def __init__(self):
        import re
        self.latex_re = re.compile('\.tex$')
        self.vhdl_re = re.compile('\.vhdl?$')
        self.is_error = False
        self.start_re = None
        self.end_re = None
        self.block_str = ''
        self.in_block = False
        self.out_str = ''
        self.parsed_file_dir = None
        Texpp.self_ = self
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

        import re
        self.start_re = re.compile('\\\\begin{texpp}')
        self.end_re = re.compile('\\\\end{texpp}')

        import os
        self.parsed_file_dir = os.path.dirname(filename)
        if len(self.parsed_file_dir) == 0: self.parsed_file_dir = '.'

        f = self.open_file(filename)
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


    def ext_to_lang(self, x):
        if self.latex_re.search(x) != None: return 'latex'
        elif self.vhdl_re.search(x) != None: return 'vhdl'
        return None


    def latex_escape(self, s):
        return s.replace('_', '\\_').replace("\t", "\\t")


    def latex_print(self, s):
        self.out_str += self.latex_escape(s) + '\\\\'


    def extract_vhdl_interface(self, file_, name):
        self.latex_print('\textbf{interface}: ' + file_.name + ', ' + name)
        return None


    def extract_vhdl_example(self, file_, name):
        self.latex_print('\textbf{example}: ' + file_.name + ', ' + name)
        return None


    def extract_(self, type_, file_, name, title):
        lang = self.ext_to_lang(file_)
        err = None
        if (lang == None) or (lang != 'vhdl'):
            err = 'invalid file extension: ' + file_
        else:
            file_ = self.parsed_file_dir + '/' + file_
            f = self.open_file(file_)
            if f == None:
                err = 'file not found ' + file_
            else:
                err = 'invalid type_'
                if type_ == 'interface':
                    err = self.extract_vhdl_interface(f, name)
                elif type_ == 'example':
                    err = self.extract_vhdl_example(f, name)

        if err != None:
            self.latex_print('\textbf{texpp error}: ' + err)
            return -1

        return 0


    @staticmethod
    def extract(type_, file_, name, title = None):
        s = Texpp.self_
        return s.extract_(type_, file_, name, title)


if __name__ == '__main__':
    import sys
    in_name = sys.argv[1]
    out_name = sys.argv[2]
    pp = Texpp()
    pp.parse_file(in_name)
    pp.output_file(out_name)
