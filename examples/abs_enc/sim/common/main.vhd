library ieee;
use ieee.std_logic_1164.all;
use ieee.std_logic_unsigned.all;
use ieee.numeric_std.all;


library work;


entity main is end main;


architecture rtl of main is


--
-- configuration constants

constant CLK_FREQ: integer := 50000000;

constant DATA_LEN: integer := 16;
constant LEN_WIDTH: integer := work.abs_enc_pkg.integer_length(DATA_LEN);

--
-- local clock and reset

signal rst: std_ulogic;
signal clk: std_ulogic;

--
-- data sent by slave to master

constant partial_data: std_logic_vector := "1001010001";

constant partial_zeros:
 std_logic_vector(DATA_LEN - 1 downto partial_data'length) :=
 (others => '0');

constant slave_data: std_logic_vector(DATA_LEN - 1 downto 0) :=
 partial_zeros & partial_data;

constant len: unsigned := to_unsigned(partial_data'length, LEN_WIDTH);

--
-- data read by master from slave

signal master_data: std_logic_vector(DATA_LEN - 1 downto 0);

--
-- master clock frequency divider
-- 1MHz clock

constant ma_fdiv: unsigned := to_unsigned(integer(50), 8);

--
-- selected encoder type

signal enc_type: integer;

--
-- master slave outputs

signal mosi: std_logic;
signal miso: std_logic;

signal ma_clk: std_logic;


begin


slave: work.abs_enc_pkg.slave
generic map
(
 CLK_FREQ => CLK_FREQ
)
port map
(
 clk => clk,
 rst => rst,
 ma_clk => ma_clk,
 miso => miso,
 mosi => mosi,
 gate => open,
 data => slave_data,
 len => len,
 enc_type => enc_type
);


master: work.abs_enc_pkg.master
generic map
(
 CLK_FREQ => CLK_FREQ
)
port map
(
 clk => clk,
 rst => rst,
 ma_fdiv => ma_fdiv,
 ma_clk => ma_clk,
 mosi => mosi,
 miso => miso,
 gate => open,
 data => master_data,
 len => len,
 enc_type => enc_type
);


end rtl;
