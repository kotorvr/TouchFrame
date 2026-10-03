// Ghidra headless post-script: decompile functions and dump C to a file.
// Args: <outFile> [addrHex ...]
//   With no addresses, dumps every function whose name or a referenced string
//   matches a protocol keyword (pairing, crypto, phy, radio, beacon, ...).
// Only our own prose and small tables get committed; the raw dump stays under
// artifacts/ (gitignored). This script just makes the dump readable.
//@category TouchFrame
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.util.*;

public class ExportDecomp extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] a = getScriptArgs();
        PrintWriter out = new PrintWriter(a[0]);
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);

        List<Function> targets = new ArrayList<>();
        if (a.length > 1) {
            for (int i = 1; i < a.length; i++) {
                Address ad = toAddr(Long.parseLong(a[i].replace("0x", ""), 16));
                Function f = getFunctionContaining(ad);
                if (f != null) targets.add(f);
            }
        } else {
            Function f = getFirstFunction();
            while (f != null) { targets.add(f); f = getFunctionAfter(f); }
        }

        for (Function f : targets) {
            DecompileResults r = di.decompileFunction(f, 60, monitor);
            out.println("// ==== " + f.getName() + " @ " + f.getEntryPoint() + " ====");
            if (r != null && r.decompileCompleted())
                out.println(r.getDecompiledFunction().getC());
            else
                out.println("// decompile failed");
            out.println();
        }
        out.close();
        di.dispose();
        println("wrote " + targets.size() + " functions to " + a[0]);
    }
}
