import sys
import re
import logging
import traceback

import base
import os
import signal

sys.path.append('./libs/')

ERROR_VALUE_NOT_FOUND = 'N/A'
ERROR_CONSTANT_NAME_NOT_FOUND = 'N/A'
ERROR_INDEX_NOT_FOUND = 'N/A'
CONST_STRING = 'const-string'
CONST = 'const'
MOVE = 'move'
MOVE_RESULT = 'move-result'
APUT = 'aput'
INVOKE = 'invoke'
INVOKE_NO_REGISTER = 'invoke-no-register'
INVOKE_2_REGISTERS = 'invoke-2-registers'
NEW_INSTANCE = 'new-instance'


class Vulnerability(object):

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    def __init__(self, name=None, description=None, level=None, resources=None):
        self.level = self.INFO if level is None else level
        self.name = name
        self.description = description
        self.resources = [] if resources is None else resources


class module(object):
    def __init__(self, apk=None, avd=None):

        self.log = logging.getLogger()
        fh = logging.FileHandler('aapt.log')
        self.log.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        self.log.addHandler(fh)
        self.loaded = False
        self.module_delimiter = '/'
        self.apk = apk
        if self.apk is not None:
            self.manifest = self.apk.get_android_manifest_xml().getElementsByTagName("manifest")[0]
        self.avd = avd
        self.subprocesses = []

    def module_run(self):
        return

    def _is_enabled(self, element):
        try:
            if element.attributes["android:enabled"].value == 'true':
                return True
            else:
                return False
        except KeyError:
            return True

    def _is_exported(self, element):
        try:
            if element.attributes["android:exported"].value == 'true':
                return True
            else:
                return False
        except KeyError:
            if len(element.getElementsByTagName("intent-filter")) > 0:
                return True
            else:
                return False

    def _get_label(self, element):
        try:
            return element.attributes["android:label"].value
        except KeyError:
            return self.manifest.getElementsByTagName("application")[0].attributes["android:label"].value

    def _get_process(self, element):
        try:
            return element.attributes["android:process"].value
        except KeyError:
            try:
                return self.manifest.getElementsByTagName("application")[0].attributes["android:process"].value
            except KeyError:
                return self.get_package()

    def _get_isolated_process(self, element):
        try:
            if element.attributes["android:isolatedProccess"].value == 'true':
                return True
            else:
                return False
        except KeyError:
            return False

    def _get_grant_uri_permissions(self, element):
        try:
            if element.attributes["android:grantUriPermissions"].value == 'true':
                return True
            else:
                return False
        except KeyError:
            return False

    def _get_permission(self, element):
        try:
            return element.attributes["android:permission"].value
        except KeyError:
            return None

    def _get_read_permission(self, element):
        try:
            return element.attributes["android:readPermission"].value
        except KeyError:
            return None

    def _get_write_permission(self, element):
        try:
            return element.attributes["android:writePermission"].value
        except KeyError:
            return None

    def get_uses_permissions(self):
        permissions = []
        for uses_permission in self.manifest.getElementsByTagName("uses-permission"):
            permissions.append(uses_permission.attributes["android:name"].value)
        return permissions

    def get_permissions(self):
        permissions = []
        for permission in self.manifest.getElementsByTagName("permission"):
            permissions.append(permission.attributes["android:name"].value)
        return permissions

    def get_package(self):

        return self.manifest.attributes["package"].value

    def get_apk_version(self):
        return self.manifest.attributes["android:versionName"].value

    def _intents(self, node):
        intentfilters = []
        for intentfilter in node.getElementsByTagName("intent-filter"):
            actions = intentfilter.getElementsByTagName("action")
            categories = intentfilter.getElementsByTagName("category")
            intentfilters.append({
                "action": actions[0].attributes["android:name"].value if len(actions) else None,
                "category": categories[0].attributes["android:name"].value if len(categories) else None
            })

        return intentfilters

    def get_activities(self):
        activities = []
        application = self.manifest.getElementsByTagName("application")[0]
        for activity in application.getElementsByTagName("activity"):
            activities.append({
                "name": activity.attributes["android:name"].value,
                "exported": True if self._is_exported(activity) else False,
                "intent_filters": self._intents(activity),
                "permission": self._get_permission(activity)
            })
        return activities

    def get_services(self):
        services = []
        application = self.manifest.getElementsByTagName("application")[0]
        for service in application.getElementsByTagName("service"):
            services.append({
                "enabled": True if self._is_enabled(service) else False,
                "exported": True if self._is_exported(service) else False,
                "label": self._get_label(service),
                "name": service.attributes["android:name"].value,
                "process": self._get_process(service),
                "isolated_process": self._get_isolated_process(service),
                "intent_filters": self._intents(service),
                "permission": self._get_permission(service)
            })
        return services

    def get_receivers(self):
        receivers = []
        application = self.manifest.getElementsByTagName("application")[0]
        for receiver in application.getElementsByTagName("receiver"):

            receivers.append({
                "enabled": True if self._is_enabled(receiver) else False,
                "exported": True if self._is_exported(receiver) else False,
                "label": self._get_label(receiver),
                "name": receiver.attributes["android:name"].value,
                "process": self._get_process(receiver),
                "permission": self._get_permission(receiver),
                "intent_filters": self._intents(receiver)
            })
        return receivers

    def get_providers(self):
        providers = []
        application = self.manifest.getElementsByTagName("application")[0]
        for provider in application.getElementsByTagName("provider"):
            providers.append({
                "enabled": True if self._is_enabled(provider) else False,
                "exported": True if self._is_exported(provider) else False,
                "label": self._get_label(provider),
                "name": provider.attributes["android:name"].value,
                "process": self._get_process(provider),
                "authorities": provider.attributes["android:authorities"].value,
                "grant_uri_permissions": self._get_grant_uri_permissions(provider),
                "permission": self._get_permission(provider),
                "read_permission": self._get_read_permission(provider),
                "write_permission": self._get_write_permission(provider),
                "uris": set()
            })
        return providers

    def get_uses_library(self):
        uses_libraries = []
        application = self.manifest.getElementsByTagName("application")[0]
        for library in application.getElementsByTagName("uses-library"):
            uses_libraries.append(library.attributes["android:name"].value)
        return uses_libraries

    def match_current_instruction(self, current_instruction, registers_found) :
        """
            @param current_instruction : the current instruction to be analyzed
            @param registers_found : a dictionary of registers recovered so far

            @rtype : the instruction name from the constants above, the local register number and its value, an updated version of the registers_found
        """
        p_const 				= re.compile('^const(?:\/4|\/16|\/high16|-wide(?:\/16|\/32)|-wide\/high16|)? v([0-9]+), \#\+?(-?[0-9]+(?:\.[0-9]+)?)$')
        p_const_string			= re.compile("^const-string(?:||-jumbo) v([0-9]+), '(.*)'$")
        p_move					= re.compile('^move(?:|\/from16|-wide(?:\/from16|\/16)|-object(?:|\/from16|\/16))? v([0-9]+), (v[0-9]+)$')
        p_move_result			= re.compile('^move(?:-result(?:|-wide|-object)|-exception)? v([0-9]+)$')
        p_aput					= re.compile('^aput(?:-wide|-object|-boolean|-byte|-char|-short|) v([0-9]+), v([0-9]+), v([0-9]+)$')
        p_invoke 				= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+), (L(?:.*);->.*)$')
        p_invoke_2_registers 	= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) v([0-9]+), v([0-9]+), (L(?:.*);->.*)$')
        p_invoke_no_register	= re.compile('^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick) (L(?:.*);->.*)$')
        p_new_instance 			= re.compile('^new-instance v([0-9]+), (L(?:.*);)$')


        # String concat
        current_instruction = "%s %s" % (current_instruction.get_name(), current_instruction.get_output())

        # Returned values init
        instruction_name = ''
        local_register_number = -1
        local_register_value = -1


        if p_const_string.match(current_instruction) :
            #print p_const_string.match(current_instruction).groups()

            instruction_name = CONST_STRING

            register_number = p_const_string.match(current_instruction).groups()[0]
            register_value = p_const_string.match(current_instruction).groups()[1]

            if not(register_number in registers_found) :
                registers_found[register_number] = register_value
            else :
                old_string = registers_found[register_number]
                new_string = "%s %s" % (str(register_value), str(old_string))
                registers_found[register_number] = new_string

            local_register_number = register_number
            local_register_value = register_value


        if p_const.match(current_instruction) :
            #print p_const.match(current_instruction).groups()

            instruction_name = CONST

            register_number = p_const.match(current_instruction).groups()[0]
            register_value = p_const.match(current_instruction).groups()[1]

            if not(register_number in registers_found) :
                registers_found[register_number] = register_value

            local_register_number = register_number
            local_register_value = register_value


        if p_move.match(current_instruction) :
            #print p_move.match(current_instruction).groups()

            instruction_name = MOVE

            register_number = p_move.match(current_instruction).groups()[0]
            register_value = p_move.match(current_instruction).groups()[1]

            if not(register_number in registers_found) :
                registers_found[register_number] = register_value

            local_register_number = register_number
            local_register_value = register_value


        if p_move_result.match(current_instruction) :
            #print p_move_result.match(current_instruction).groups()

            instruction_name = MOVE_RESULT

            register_number = p_move_result.match(current_instruction).groups()[0]
            register_value = ''

            if not(register_number in registers_found) :
                registers_found[register_number] = register_value

            local_register_number = register_number
            local_register_value = register_value
            #print "number returned %s" % local_register_number
            #print "value returned %s" % local_register_value

        if p_invoke.match(current_instruction) :
            #print p_invoke.match(current_instruction).groups()

            instruction_name = INVOKE

            register_number = p_invoke.match(current_instruction).groups()[0]
            register_value = p_invoke.match(current_instruction).groups()[1]

            if not(register_number in registers_found) :
                registers_found[register_number] = register_value

            local_register_number = register_number
            local_register_value = register_value

        if p_invoke_no_register.match(current_instruction) :
            #print p_invoke.match(current_instruction).groups()

            instruction_name = INVOKE_NO_REGISTER

            register_number = ''
            register_value = p_invoke_no_register.match(current_instruction).groups()[0]

            local_register_number = register_number
            local_register_value = register_value

        if p_invoke_2_registers.match(current_instruction) :
            #print p_invoke.match(current_instruction).groups()

            instruction_name = INVOKE_NO_REGISTER

            register_number = p_invoke_2_registers.match(current_instruction).groups()[0]
            register_value = p_invoke_2_registers.match(current_instruction).groups()[1]

            local_register_number = register_number
            local_register_value = register_value

        if p_new_instance.match(current_instruction) :
            #print p_new_instance.match(current_instruction).groups()

            instruction_name = NEW_INSTANCE

            register_number = p_new_instance.match(current_instruction).groups()[0]
            register_value = p_new_instance.match(current_instruction).groups()[1]

            if not(register_number in registers_found) :
                registers_found[register_number] = register_value

            local_register_number = register_number
            local_register_value = register_value

        if p_aput.match(current_instruction) :
            #print p_aput.match(current_instruction).groups()

            instruction_name = APUT

            register_object_reference = p_aput.match(current_instruction).groups()[0]
            register_array_reference = p_aput.match(current_instruction).groups()[1]
            register_element_index = p_aput.match(current_instruction).groups()[2]

            local_register_number = register_object_reference
            local_register_value =  register_array_reference


        return instruction_name, local_register_number, local_register_value, registers_found

    def extract_register_index_out_splitted_values(self, registers_raw_list_splitted) :
        """
            @param : registers_raw_list_splitted : a list of registers still containing the 'v' prefix [' v1 ', ' v2 ' ...]

            @rtype : an ordered list of register indexes ['1', '2' ...]
        """
        relevant_registers = []

        # Trim the values
        registers_raw_list_splitted[:] = (value.strip() for value in registers_raw_list_splitted if len(value) > 0)

        for value in registers_raw_list_splitted :

            # Remove that 'v'
            p_register_index_out_of_split = re.compile('^v([0-9]+)$')

            if p_register_index_out_of_split.match(value) :
                #print p_register_index_out_of_split.match(value).groups()
                register_index = p_register_index_out_of_split.match(value).groups()[0]

                relevant_registers.append(register_index)

            else :
                relevant_registers.append('N/A')

        return relevant_registers

    def relevant_registers_for_the_method(self, instruction):
        """
            @param method : a method instance
            @param index_to_find : index of the matching method

            @rtype : an ordered list of register indexes related to that method call
        """
        relevant_registers = []

        current_instruction_name = instruction.get_name()
        current_instruction = instruction.show_buff(0)

        p_invoke_name = re.compile(
            '^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick)$')
        p_invoke_range_name = re.compile(
            '^invoke-(?:static|virtual|direct|super|interface|interface-range|virtual-quick|super-quick)(?:\/range)$')

        if p_invoke_name.match(current_instruction_name):

            p_invoke_registers = re.compile('(v[0-9]+),')

            if p_invoke_registers.findall(current_instruction):
                registers_raw_list_splitted = p_invoke_registers.findall(current_instruction)
                relevant_registers = self.extract_register_index_out_splitted_values(registers_raw_list_splitted)

        if p_invoke_range_name.match(current_instruction_name):
            # We're facing implicit an implicit range declaration, for instance "invoke v19..v20"
            p_invoke_registers_range = re.compile('^v([0-9]+) ... v([0-9]+), L.*$')

            if p_invoke_registers_range.match(current_instruction):
                register_start_number = p_invoke_registers_range.match(current_instruction).groups()[0]
                register_end_number = p_invoke_registers_range.match(current_instruction).groups()[1]

                if int(register_start_number) > int(register_end_number):
                    self.error("invoke-kind/range incoherent: # of the start register is lower than the end one")
                else:
                    relevant_registers = [str(i) for i in xrange(int(register_start_number), int(register_end_number))]
                    # +1 because range does not provide the higher boundary value

        return relevant_registers

    def all_relevant_registers_filled(self, registers, relevant_registers):
        """
        @param registers : a dictionary of each register content { 'register #': 'value' }
        @param relevant_registers : an ordered list of register indexes related to that method call

        @rtype : True if all the relevant_registers are filled, False if not
        """
        answer = True

        for i in relevant_registers:
            # assert a False answer for null registers from the "move-result" instruction
            if not (i in registers) or (i in registers and len(registers[i]) < 1):
                answer = False

        return answer

    def get_register_value(self, index, registers):
        """
            @param index : integer value of the index
            @param registers : an ordered list of register indexes related to that method call

            @rtype : a value casted in string
        """
        # Index - 1, list starts at index 0
        if index <= len(registers):
            dict = registers[index]
            return dict.values()[0]
        else:
            return ERROR_VALUE_NOT_FOUND

    def get_constants_name_from_value(self, constant_dict, value):
        """
            @param constant_dict : constant dictionary to consider
            @param value : value's constant name to retrieve

            @rtype : a string
        """
        try:
            return constant_dict[value]

        except KeyError:
            self.error("The constant name corresponding to the value '%s' can not be found in the dictionary '%s'" % (
            value, constant_dict))
            return ERROR_CONSTANT_NAME_NOT_FOUND

    def find_call_index_in_code_list(self, index_to_find, instruction_list):
        """
        @param index_to_find : index of the method call
        @param code_list : instruction list of the parent method called

        @rtype : the index of the method call in the instruction listing
        """
        idx = 0
        for i in instruction_list:
            if index_to_find <= idx:
                # print "[+] code offset found at the index " + str(instruction_list.index(i))
                return instruction_list.index(i)
            else:
                idx += i.get_length()
        return ERROR_INDEX_NOT_FOUND

    def backtrace_registers_before_call(self, x, method, index_to_find):
        """
            @param x : a VMAnalysis instance
            @param method : a regexp for the method (the package)
            @param index_to_find : index of the matching method

            @rtype : an ordered list of dictionaries of each register content [{ 'register #': 'value' }, { 'register #': 'value' } ...]
        """
        registers = {}

        code = method.get_code()
        # code.show()

        bc = code.get_bc()
        instruction_list = [i for i in bc.get_instructions()]

        found_index = self.find_call_index_in_code_list(index_to_find, instruction_list)

        if (found_index < 0):
            return 0

        else:
            # Initialize the returned list of dictionaries
            registers_final = []

            # Initialize the harvesting dictionary
            registers_found = {}

            # List the register indexes related to the method call
            relevant_registers = self.relevant_registers_for_the_method(instruction_list[found_index])

            # print relevant_registers

            i = int(found_index) - 1  # start index

            while ((self.all_relevant_registers_filled(registers_found, relevant_registers) != True) and (i >= 0)):
                # current_instruction = instruction_list[i].show_buff(0)
                #print current_instruction
                current_instruction = instruction_list[i]

                instruction_name, local_register_number, local_register_value, registers_found = self.match_current_instruction(
                    current_instruction, registers_found)

                if cmp(instruction_name, APUT) == 0:
                    try:
                        list_index_to_be_changed = relevant_registers.index(str(local_register_value))
                        #print "index_to_be_changed %s" % list_index_to_be_changed
                        del (relevant_registers[int(local_register_value)])
                        relevant_registers.insert(list_index_to_be_changed, local_register_number)
                        self.alert("New relevant_registers %s" % relevant_registers)
                    except:
                        self.alert("'%s' does not exist anymore in the relevant_registers list" % local_register_value)

                if (cmp(instruction_name, MOVE_RESULT) == 0) and (local_register_number in relevant_registers):
                    try:
                        #past_instruction = instruction_list[i-1].show_buff(0)
                        #print past_instruction
                        past_instruction = instruction_list[i - 1]
                        p_instruction_name, p_local_register_number, p_local_register_value, registers_found = self.match_current_instruction(
                            past_instruction, registers_found)

                        if cmp(p_instruction_name, INVOKE_NO_REGISTER) == 0:
                            registers_found[local_register_number] = p_local_register_value

                        else:
                            list_index_to_be_changed = relevant_registers.index(str(local_register_number))
                            del (relevant_registers[int(list_index_to_be_changed)])
                            relevant_registers.insert(list_index_to_be_changed, p_local_register_number)

                        self.alert("New relevant_registers %s" % relevant_registers)

                    except:
                        self.alert("'%s' does not exist anymore in the relevant_registers list" % local_register_value)

                i = i - 1

            # log.info('Registers found during the analysis %s' % registers_found)



            final_answer = self.all_relevant_registers_filled(registers_found, relevant_registers)
            self.alert("Are all relevant registers filled ? %s" % str(final_answer))

            for i in relevant_registers:
                try:
                    register_number = i
                    #print register_number

                    register_value = registers_found[i]
                    #print register_value

                    temp_dict = {register_number: register_value}
                    registers_final.append(temp_dict)

                except KeyError:
                    registers_final = []
                    self.error(
                        "KeyError exception : The value of the register # %s could not be found for the relevant registers %s" % (
                            register_number, relevant_registers))
                    break

            return registers_final

    def data_flow_analysis(self, tab, result, x):
        """
        @param tab : structural analysis results tab
        @param result : current iteration
        @param x : a VMAnalysis instance
        @rtype : an ordered list of dictionaries of each register content [{ 'register #': 'value' }, { 'register #': 'value' } ...]
        """
        method = tab[result].get_method()
        method_call_index_to_find = tab[result].get_idx()
        registers = self.backtrace_registers_before_call(x, method, method_call_index_to_find)
        class_str = "Class '%s'" % tab[result].get_class_name()
        method_str = "Method '%s'" % tab[result].get_name()
        regs_str = "Register state before call %s" % registers
        formatted_str = "{0:50}- {1:35}- {2:30}".format(class_str, method_str, regs_str)
        return registers

    def to_unicode(self, obj, encoding='utf-8'):
        # checks if obj is a unicode string and converts if not
        if isinstance(obj, basestring):
            if not isinstance(obj, unicode):
                obj = unicode(obj, encoding)
                return obj

    def ascii_sanitize(self, s):
        return ''.join([char for char in s if ord(char) in [10, 13] + range(32, 126)])

    def html_escape(self, s):
        escapes = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&apos;",
            ">": "&gt;",
            "<": "&lt;",
        }
        return "".join(escapes.get(c, c) for c in s)

    def error(self, line):
        '''Formats and presents errors.'''
        error = "%s\n\n%s" %(traceback.format_exc(), line)
        print '%s[!] %s%s' % (R, self.to_unicode(error), N)
        self.log.error(line)
        if self.avd is not None:
            self.avd.shutdown()
        for pid in self.subprocesses:
                os.kill(pid+1, signal.SIGTERM)
        sys.exit(-1)

    def warning(self, line):
        ''' TODO '''
        print '%s[#] %s%s' % (O, self.to_unicode(line), N)
        self.log.warning(line)

    def output(self, line):
        '''Formats and presents normal output.'''
        print '%s[*]%s %s' % (B, N, self.to_unicode(line))
        self.log.info(line)

    def alert(self, line):
        '''Formats and presents important output.'''
        print '%s[*]%s %s' % (G, N, self.to_unicode(line))
        self.log.info(line)

    def verbose(self, line):
        '''Formats and presents output if in verbose mode.'''
        self.output(line)
