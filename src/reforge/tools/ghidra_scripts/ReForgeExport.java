// Nexonic ReForge Studio - Ghidra headless export script.
// Writes functions, call graph and decompilation of the largest functions as JSON.
// Args: <output.json> [maxDecompiledFunctions=25] [decompileTimeoutSec=30]
// Output is a decompiled representation, never original source code.
//@category ReForge
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class ReForgeExport extends GhidraScript {
    private static final int MAX_FUNCTIONS = 20000;
    private static final int MAX_CALLS = 50;

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        File out = new File(a[0]);
        int maxDec = a.length > 1 ? Integer.parseInt(a[1]) : 25;
        int decTimeout = a.length > 2 ? Integer.parseInt(a[2]) : 30;

        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> fs = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            fs.add(f);
            if (fs.size() >= MAX_FUNCTIONS) break;
        }
        List<Function> bySize = new ArrayList<>(fs);
        bySize.removeIf(f -> f.isThunk() || f.isExternal());
        bySize.sort((x, y) -> Long.compare(y.getBody().getNumAddresses(), x.getBody().getNumAddresses()));
        Set<Function> decSet = new HashSet<>(bySize.subList(0, Math.min(maxDec, bySize.size())));

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(out), "UTF-8"))) {
            w.print("{\"program\":\"" + esc(currentProgram.getName()) + "\"");
            w.print(",\"language\":\"" + esc(currentProgram.getLanguageID().toString()) + "\"");
            w.print(",\"compiler\":\"" + esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\"");
            w.print(",\"image_base\":\"" + currentProgram.getImageBase() + "\"");
            w.print(",\"function_count\":" + fm.getFunctionCount());
            w.print(",\"functions\":[");
            boolean first = true;
            for (Function f : fs) {
                if (monitor.isCancelled()) break;
                if (!first) w.print(",");
                first = false;
                StringBuilder calls = new StringBuilder();
                int c = 0;
                for (Function g : f.getCalledFunctions(monitor)) {
                    if (c >= MAX_CALLS) break;
                    if (c++ > 0) calls.append(",");
                    calls.append("\"").append(esc(g.getName())).append("\"");
                }
                w.print("{\"name\":\"" + esc(f.getName()) + "\",\"entry\":\"" + f.getEntryPoint() + "\"");
                w.print(",\"size\":" + f.getBody().getNumAddresses());
                w.print(",\"thunk\":" + f.isThunk() + ",\"external\":" + f.isExternal());
                w.print(",\"signature\":\"" + esc(f.getSignature().getPrototypeString()) + "\"");
                w.print(",\"calls\":[" + calls + "]");
                if (decSet.contains(f)) {
                    DecompileResults r = di.decompileFunction(f, decTimeout, monitor);
                    if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                        w.print(",\"decompiled\":\"" + esc(r.getDecompiledFunction().getC()) + "\"");
                    }
                }
                w.print("}");
            }
            w.print("]}");
        } finally {
            di.dispose();
        }
    }
}
