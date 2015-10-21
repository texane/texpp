--
-- ssi master implementation


library ieee;
use ieee.std_logic_1164.all;
use ieee.std_logic_unsigned.all;
use ieee.numeric_std.all;
use ieee.math_real.all;

library work;


entity master_ssi is

generic
(
 CLK_FREQ: integer
);
port
(
 -- local clock
 clk: in std_logic;
 rst: in std_logic;

 -- master clock edges
 ma_clk_fedge: in std_logic;
 ma_clk_redge: in std_logic;

 -- master clock reset
 -- if ma_clk_rst_en, use ma_clk_rst_level
 ma_clk_rst_en: out std_logic;
 ma_clk_rst_val: out std_logic;

 -- master out, slave in
 mosi: out std_logic;
 miso: in std_logic;

 -- gate to drive output (1 to drive it)
 gate: out std_logic;

 -- desired data length
 len: in unsigned;

 -- timeout counter
 tm_match: in std_logic;
 tm_top: out unsigned;

 -- general purpose counter
 count_top: out unsigned;
 count_match: in std_logic;
 count_rst: out std_logic;

 -- sipo register
 sipo_val: in std_logic_vector;
 sipo_latch: out std_logic;

 -- enable data conversion stages
 gray_to_bin_en: out std_logic;
 lsb_to_msb_en: out std_logic
);

end entity;


architecture abs_enc_master_ssi_rtl of master_ssi is


--
-- default timeout value. standard says:
-- https://upload.wikimedia.org/wikipedia/commons/8/8d/Ssisingletransmission.jpg

constant TM_VAL: integer := work.abs_enc_pkg.us_to_count
 (work.abs_enc_pkg.MASTER_DEFAULT_TM_US, CLK_FREQ, tm_top'length);


--
-- state machine

type ssi_state_t is
(
 SSI_START,
 SSI_DATA,
 SSI_TP
);

constant SSI_ERR: ssi_state_t := SSI_START;

signal curr_state: ssi_state_t;
signal next_state: ssi_state_t;


begin


--
-- state automaton

process
begin
 wait until rising_edge(clk);

 if (rst = '1') then
  curr_state <= SSI_START;
 elsif ((ma_clk_redge or tm_match) = '1') then
  curr_state <= next_state;
 end if;

end process;


process(curr_state, count_match)
begin
 
 next_state <= curr_state;

 case curr_state is

  when SSI_START =>
   next_state <= SSI_DATA;

  when SSI_DATA =>
   if count_match = '1' then
    next_state <= SSI_TP;
   end if;

  when SSI_TP =>
   next_state <= SSI_START;

  when others =>
   next_state <= SSI_ERR;

 end case;

end process;


process
begin
 wait until rising_edge(clk);

 ma_clk_rst_en <= '0';
 count_top <= (others => '0');
 count_rst <= '0';
 sipo_latch <= '0';

 case curr_state is

  when SSI_START =>
   count_top <= len(count_top'range);
   count_rst <= '1';

  when SSI_DATA =>

  when SSI_TP =>
   sipo_latch <= '1';
   ma_clk_rst_en <= '1';

  when others =>

 end case;

end process;


--
-- clock reset or idle value

ma_clk_rst_val <= '1';


--
-- timeout

tm_top <= to_unsigned(TM_VAL, tm_top'length);


--
-- gray to binary disabled

gray_to_bin_en <= '0';


--
-- lsb to msb disabled

lsb_to_msb_en <= '0';


--
-- gate always disabled

gate <= '0';
mosi <= '0';


end architecture;
