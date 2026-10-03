// Decompile every function that references a string containing one of the given needles,
// plus any functions at explicitly listed addresses. Output goes to one text file.
// Usage (headless postScript): DumpByStrings.java <outfile> <needlesfile> [hexaddr ...]
// needlesfile: one substring per line. Used for TouchFrame interop research; outputs stay in artifacts/.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class DumpByStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter out = new PrintWriter(new FileWriter(args[0]));
        List<String> needles = Files.readAllLines(Paths.get(args[1]));
        needles.removeIf(s -> s.trim().isEmpty());
        Listing listing = currentProgram.getListing();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Map<Function, Set<String>> funcs = new LinkedHashMap<>();
        DataIterator it = listing.getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            if (!(d.getValue() instanceof String)) continue;
            String s = (String) d.getValue();
            for (String n : needles) {
                if (s.contains(n)) {
                    for (Reference r : rm.getReferencesTo(d.getAddress())) {
                        Function f = listing.getFunctionContaining(r.getFromAddress());
                        if (f != null) funcs.computeIfAbsent(f, k -> new TreeSet<>()).add(s);
                        else out.println("// unowned ref to \"" + s + "\" from " + r.getFromAddress());
                    }
                    break;
                }
            }
        }
        for (int i = 2; i < args.length; i++) {
            if (args[i].startsWith("x")) { // "x<addr>": also dump every function that references <addr>
                Address t = toAddr(args[i].substring(1));
                for (Reference r : rm.getReferencesTo(t)) {
                    Function f = listing.getFunctionContaining(r.getFromAddress());
                    if (f != null) funcs.computeIfAbsent(f, k -> new TreeSet<>()).add("<xref to " + t + " from " + r.getFromAddress() + ">");
                }
                continue;
            }
            Address a = toAddr(args[i]);
            Function f = listing.getFunctionContaining(a);
            if (f == null) { f = createFunction(a, null); }
            if (f != null) funcs.computeIfAbsent(f, k -> new TreeSet<>()).add("<addr " + args[i] + ">");
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        for (Map.Entry<Function, Set<String>> e : funcs.entrySet()) {
            Function f = e.getKey();
            out.println("//==== " + f.getName() + " @ " + f.getEntryPoint() + " size " + f.getBody().getNumAddresses());
            for (String s : e.getValue()) out.println("//  str: " + s.replace("\n", "\\n"));
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            if (res != null && res.decompileCompleted()) out.println(res.getDecompiledFunction().getC());
            else out.println("// decompile failed");
            out.flush();
        }
        out.close();
        println("dumped " + funcs.size() + " functions");
    }
}
