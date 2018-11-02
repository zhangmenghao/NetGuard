# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift PD interface DV test
"""

import logging
import os
import pd_base_tests
import pltfm_pm_rpc
import pal_rpc
import random
import sys
import time
import unittest

from synproxy.p4_pd_rpc.ttypes import *
from pltfm_pm_rpc.ttypes import *
from pal_rpc.ttypes import *
from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
from res_pd_rpc.ttypes import *

this_dir = os.path.dirname(os.path.abspath(__file__))

# Front Panel Ports
#   List of front panel ports to use. Each front panel port has 4 channels.
#   Port 1 is broken to 1/0, 1/1, 1/2, 1/3. Test uses 2 ports.
#
#   ex: ["1/0", "1/1"]
#
fp_ports = ["1/0","2/0","3/0", "4/0"]


class L2Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        # initialize the thrift data plane
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self,
                                                        ["synproxy"])

    def cleanup_table(self, table):
        table = 'self.client.' + table
        # get entry count
        num_entries = eval(table + '_get_entry_count')\
                      (self.sess_hdl, self.dev_tgt)
        print "Number of entries : {}".format(num_entries)
        if num_entries == 0:
            return
        # get the entry handles
        hdl = eval(table + '_get_first_entry_handle')\
                (self.sess_hdl, self.dev_tgt)
        if num_entries > 1:
            hdls = eval(table + '_get_next_entry_handles')\
                (self.sess_hdl, self.dev_tgt, hdl, num_entries - 1)
            hdls.insert(0, hdl)
        else:
            hdls = [hdl]
        # delete the table entries
        for hdl in hdls:
            entry = eval(table + '_get_entry')\
                (self.sess_hdl, self.dev_tgt.dev_id, hdl, True)
            eval(table + '_table_delete_by_match_spec')\
                (self.sess_hdl, self.dev_tgt, entry.match_spec)

    def setUp(self):
        # initialize the connection
        pd_base_tests.ThriftInterfaceDataPlane.setUp(self)
        self.sess_hdl = self.conn_mgr.client_init()
        self.dev_tgt = DevTarget_t(0, hex_to_i16(0xFFFF))
        self.devPorts = []

        self.platform_type = "mavericks"
        board_type = self.pltfm_pm.pltfm_pm_board_type_get()
        if re.search("0x0234|0x1234|0x4234|0x5234", hex(board_type)):
            self.platform_type = "mavericks"
        elif re.search("0x2234|0x3234", hex(board_type)):
            self.platform_type = "montara"

        # get the device ports from front panel ports
        try:
            for fpPort in fp_ports:
                port, chnl = fpPort.split("/")
                devPort = \
                    self.pal.pal_port_front_panel_port_to_dev_port_get(0,
                                                                    int(port),
                                                                    int(chnl))
                self.devPorts.append(devPort)

            if test_param_get('setup') == True or (test_param_get('setup') != True
                and test_param_get('cleanup') != True):

                # add and enable the platform ports
                for i in self.devPorts:
                    self.pal.pal_port_add(0, i,
                                        pal_port_speed_t.BF_SPEED_40G,
                                        pal_fec_type_t.BF_FEC_TYP_NONE)
                    self.pal.pal_port_enable(0, i)
                self.conn_mgr.complete_operations(self.sess_hdl)
        except Exception as e:
            pass

    def runTest(self):
	self.client.init_set_default_action_init_action_(self.sess_hdl,self.dev_tgt,
	synproxy_init_action__action_spec_t(16000,16000));

	self.client.session_init_table_set_default_action_sendback_sa(self.sess_hdl,self.dev_tgt);
	self.client.session_complete_table_set_default_action_sendh2syn(self.sess_hdl,self.dev_tgt);
	self.client.relay_session_table_set_default_action_sendh2ack(self.sess_hdl,self.dev_tgt);
	self.client.inbound_tran_table_set_default_action_inbound_transformation(self.sess_hdl,self.dev_tgt);
	self.client.outbound_tran_table_set_default_action_outbound_transformation(self.sess_hdl,self.dev_tgt);

	self.client.session_check_set_default_action_lookup_session_map(self.sess_hdl,self.dev_tgt);
	self.client.session_check_reverse_set_default_action_lookup_session_map_reverse(self.sess_hdl,self.dev_tgt);
	self.client.set_heavy_hitter_count_table_1_set_default_action_set_heavy_hitter_count_1(self.sess_hdl,self.dev_tgt);
	self.client.set_heavy_hitter_count_table_2_set_default_action_set_heavy_hitter_count_2(self.sess_hdl,self.dev_tgt);
	self.client.acl_set_default_action_nop(self.sess_hdl,self.dev_tgt);

	self.client.update_countt_set_default_action_update_countt(self.sess_hdl, self.dev_tgt)
	self.client.time32_in_set_default_action_time32_in(self.sess_hdl, self.dev_tgt)
	#self.client.write_time_in_set_default_action_write_time_in(self.sess_hdl, self.dev_tgt)
	self.client.time32_eg_set_default_action_time32_eg(self.sess_hdl, self.dev_tgt)
	#self.client.write_time_eg_set_default_action_write_time_eg(self.sess_hdl, self.dev_tgt)
        self.conn_mgr.complete_operations(self.sess_hdl)
        while(True):
            pass




    def tearDown(self):
        print

        if (test_param_get('setup') != True and \
            test_param_get('cleanup') != True) \
            or test_param_get('cleanup') == True:

            print "Cleaning up"

            # delete the programmed forward table entry
            self.cleanup_table("forward")
            # delete the platform ports
            self.conn_mgr.client_cleanup(self.sess_hdl)
            for i in self.devPorts:
                self.pal.pal_port_del(0, i)
            self.pal.pal_port_del_all(0)
