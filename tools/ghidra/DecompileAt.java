// Decompile functions at listed addresses in a program imported WITHOUT auto-analysis
// (for very large stripped binaries). Disassembles and creates each function on demand.
// Usage (headless postScript): DecompileAt.java <outfile> <addrfile>   (one hex address per line)
// Used for TouchFrame interop research; outputs stay in artifacts/ (gitignored).
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class DecompileAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(args[0]));
        List<String> lines = Files.readAllLines(Paths.get(args[1]));
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Listing listing = currentProgram.getListing();
        for (String l : lines) {
            l = l.trim();
            if (l.isEmpty() || l.startsWith("#")) continue;
            Address a = toAddr(l);
            Function f = listing.getFunctionAt(a);
            if (f == null) {
                new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
                f = createFunction(a, null);
            }
            if (f == null) { out.println("//==== no function at " + a); continue; }
            out.println("//==== " + f.getName() + " @ " + a + " size " + f.getBody().getNumAddresses());
            DecompileResults r = di.decompileFunction(f, 180, monitor);
            out.println(r != null && r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed");
            out.flush();
        }
        out.close();
    }
}
