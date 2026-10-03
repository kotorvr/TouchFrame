// Ghidra headless pre-script for raw nRF52 (Cortex-M, Thumb) flash images.
// Args: <vectorTableAddrHex> [funcsFile]
//   funcsFile: optional text file of "0xADDR 0xSIZE" lines (from unwind tables)
// Adds RAM + peripheral memory blocks, labels nRF52 RADIO / CCM / AAR / ECB / FICR
// registers so the analyst can grep for PHY and crypto config writes, then creates
// functions from the vector table and the optional unwind list.
//@category TouchFrame
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import java.io.BufferedReader;
import java.io.FileReader;

public class SetupCortexM extends GhidraScript {

    private void block(String name, long start, long len) throws Exception {
        Memory mem = currentProgram.getMemory();
        Address a = toAddr(start);
        if (mem.getBlock(a) != null) return;
        MemoryBlock b = mem.createUninitializedBlock(name, a, len, false);
        b.setRead(true);
        b.setWrite(true);
        b.setExecute(false);
        b.setVolatile(true);
    }

    private void lbl(long addr, String name) throws Exception {
        currentProgram.getSymbolTable().createLabel(toAddr(addr), name, SourceType.IMPORTED);
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        long vector = Long.parseLong(args[0].replace("0x", ""), 16);

        // SRAM and the peripheral/FICR regions so absolute refs resolve.
        block("RAM", 0x20000000L, 0x40000L);
        block("APB", 0x40000000L, 0x80000L);
        block("AHB", 0x50000000L, 0x10000L);
        block("FICR", 0x10000000L, 0x1000L);
        block("UICR", 0x10001000L, 0x1000L);

        // nRF52 peripheral registers most relevant to the radio protocol.
        lbl(0x40001000L, "RADIO");
        lbl(0x40001504L, "RADIO_PACKETPTR");
        lbl(0x40001508L, "RADIO_FREQUENCY");
        lbl(0x4000150CL, "RADIO_TXPOWER");
        lbl(0x40001510L, "RADIO_MODE");
        lbl(0x40001514L, "RADIO_PCNF0");
        lbl(0x40001518L, "RADIO_PCNF1");
        lbl(0x4000151CL, "RADIO_BASE0");
        lbl(0x40001520L, "RADIO_BASE1");
        lbl(0x40001524L, "RADIO_PREFIX0");
        lbl(0x40001528L, "RADIO_PREFIX1");
        lbl(0x4000152CL, "RADIO_TXADDRESS");
        lbl(0x40001530L, "RADIO_RXADDRESSES");
        lbl(0x40001534L, "RADIO_CRCCNF");
        lbl(0x40001538L, "RADIO_CRCPOLY");
        lbl(0x4000153CL, "RADIO_CRCINIT");
        lbl(0x40001550L, "RADIO_DATAWHITEIV");
        lbl(0x40001000L + 0x560, "RADIO_MODECNF0");
        lbl(0x4000F000L, "CCM");
        lbl(0x4000F004L, "CCM_TASKS_CRYPT");
        lbl(0x4000F504L, "CCM_MODE");
        lbl(0x4000F508L, "CCM_CNFPTR");
        lbl(0x4000F50CL, "CCM_INPTR");
        lbl(0x4000F510L, "CCM_OUTPTR");
        lbl(0x4000F514L, "CCM_SCRATCHPTR");
        lbl(0x4000E000L, "AAR");
        lbl(0x4000E000L + 0x504, "AAR_NIRK");
        lbl(0x4000E000L + 0x508, "AAR_IRKPTR");
        lbl(0x4000E000L + 0x510, "AAR_ADDRPTR");
        lbl(0x4000E000L, "ECB");
        lbl(0x4000E004L, "ECB_TASKS_STARTECB");
        lbl(0x4000E508L, "ECB_ECBDATAPTR");
        lbl(0x4000B000L, "RNG");
        lbl(0x40009000L, "TEMP");
        lbl(0x10000060L, "FICR_DEVICEID0");
        lbl(0x10000064L, "FICR_DEVICEID1");
        lbl(0x100000A4L, "FICR_DEVICEADDR0");
        lbl(0x100000A8L, "FICR_DEVICEADDR1");

        // Entry from the vector table reset vector (offset +4).
        Address rstPtr = toAddr(vector + 4);
        long reset = getInt(rstPtr) & 0xffffffffL;
        Address resetFn = toAddr(reset & ~1L);
        disassemble(resetFn);
        createFunction(resetFn, "reset_handler");
        println("reset_handler @ " + resetFn);

        // Optional: exact function boundaries from an unwind table.
        if (args.length > 1) {
            BufferedReader br = new BufferedReader(new FileReader(args[1]));
            String line;
            int n = 0;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] p = line.split("\\s+");
                long a = Long.parseLong(p[0].replace("0x", ""), 16) & ~1L;
                Address fa = toAddr(a);
                try {
                    disassemble(fa);
                    if (getFunctionAt(fa) == null) createFunction(fa, null);
                    n++;
                } catch (Exception e) { /* skip bad entries */ }
            }
            br.close();
            println("created " + n + " functions from " + args[1]);
        }
    }
}
