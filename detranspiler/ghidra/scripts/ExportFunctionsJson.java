import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class ExportFunctionsJson extends ghidra.app.script.GhidraScript {
    private static class Xref {
        public final String from;
        public final String type;

        public Xref(String from, String type) {
            this.from = from;
            this.type = type;
        }
    }

    private static String _escapeJson(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\\\");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                    break;
            }
        }
        return sb.toString();
    }

    private static void _jsonString(PrintWriter out, String s) {
        if (s == null) {
            out.print("null");
            return;
        }
        out.print('"');
        out.print(_escapeJson(s));
        out.print('"');
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 1) {
            printerr("Missing output file argument");
            return;
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        int maxFunctions = 20000;
        if (args.length >= 2) {
            try {
                maxFunctions = Integer.parseInt(args[1]);
            } catch (Exception e) {
                maxFunctions = 20000;
            }
        }

        int maxXrefsPerFunction = 200;
        if (args.length >= 3) {
            try {
                maxXrefsPerFunction = Integer.parseInt(args[2]);
            } catch (Exception e) {
                maxXrefsPerFunction = 200;
            }
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Listing listing = currentProgram.getListing();

        List<Function> functions = new ArrayList<>();
        Map<Address, Function> byEntry = new HashMap<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Function f = it.next();
            if (f == null) {
                continue;
            }
            Address entry = f.getEntryPoint();
            if (entry == null) {
                continue;
            }
            functions.add(f);
            byEntry.put(entry, f);
            if (functions.size() >= maxFunctions) {
                break;
            }
        }

        Map<Address, Set<Address>> callers = new HashMap<>();
        Map<Address, Set<Address>> callees = new HashMap<>();
        Set<String> edgeSet = new HashSet<>();
        List<Address[]> edges = new ArrayList<>();

        Map<Address, List<Xref>> xrefsToEntry = new HashMap<>();
        Map<Address, Integer> xrefsTotal = new HashMap<>();

        for (Function f : functions) {
            if (monitor.isCancelled()) {
                break;
            }
            Address target = f.getEntryPoint();
            if (target == null) {
                continue;
            }

            List<Xref> xrefs = new ArrayList<>();
            int total = 0;

            ReferenceIterator refs = rm.getReferencesTo(target);
            while (refs.hasNext()) {
                if (monitor.isCancelled()) {
                    break;
                }
                Reference r = refs.next();
                if (r == null) {
                    continue;
                }
                total += 1;

                RefType rt = r.getReferenceType();
                String rtStr = rt != null ? rt.toString() : "";
                if (xrefs.size() < maxXrefsPerFunction) {
                    xrefs.add(new Xref(r.getFromAddress().toString(), rtStr));
                }

                if (rt != null && rt.isCall()) {
                    Function caller = fm.getFunctionContaining(r.getFromAddress());
                    if (caller == null || caller.getEntryPoint() == null) {
                        continue;
                    }
                    Address callerEntry = caller.getEntryPoint();

                    callers.computeIfAbsent(target, k -> new HashSet<>()).add(callerEntry);
                    callees.computeIfAbsent(callerEntry, k -> new HashSet<>()).add(target);

                    String edgeKey = callerEntry.toString() + "->" + target.toString();
                    if (!edgeSet.contains(edgeKey)) {
                        edgeSet.add(edgeKey);
                        edges.add(new Address[] { callerEntry, target });
                    }
                }
            }

            xrefsToEntry.put(target, xrefs);
            xrefsTotal.put(target, total);
        }

        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            out.println("{");
            out.println("  \"program\": {");
            out.print("    \"name\": ");
            _jsonString(out, currentProgram.getName());
            out.println(",");
            out.print("    \"language_id\": ");
            _jsonString(out, currentProgram.getLanguageID().toString());
            out.println(",");
            out.print("    \"compiler_spec_id\": ");
            _jsonString(out, currentProgram.getCompilerSpec().getCompilerSpecID().toString());
            out.println(",");
            out.print("    \"image_base\": ");
            _jsonString(out, currentProgram.getImageBase().toString());
            out.println("");
            out.println("  },");

            out.print("  \"functions_total\": ");
            out.print(functions.size());
            out.println(",");

            out.println("  \"functions\": [");
            for (int i = 0; i < functions.size(); i++) {
                if (monitor.isCancelled()) {
                    break;
                }
                Function f = functions.get(i);
                Address entry = f.getEntryPoint();

                out.println("    {");
                out.print("      \"name\": ");
                _jsonString(out, f.getName());
                out.println(",");

                out.print("      \"entry\": ");
                _jsonString(out, entry != null ? entry.toString() : null);
                out.println(",");

                out.print("      \"return_type\": ");
                _jsonString(out, f.getReturnType() != null ? f.getReturnType().getDisplayName() : null);
                out.println(",");

                out.print("      \"calling_convention\": ");
                _jsonString(out, f.getCallingConventionName());
                out.println(",");

                out.print("      \"parameters\": [");
                Parameter[] params = f.getParameters();
                for (int pi = 0; pi < params.length; pi++) {
                    Parameter p = params[pi];
                    out.print("{");
                    out.print("\"name\": ");
                    _jsonString(out, p != null ? p.getName() : null);
                    out.print(", \"data_type\": ");
                    _jsonString(out, (p != null && p.getDataType() != null) ? p.getDataType().getDisplayName() : null);
                    out.print(", \"length\": ");
                    out.print(p != null ? p.getLength() : 0);
                    out.print(", \"storage\": ");
                    try {
                        _jsonString(out, (p != null && p.getVariableStorage() != null) ? p.getVariableStorage().toString() : null);
                    } catch (Exception e) {
                        _jsonString(out, null);
                    }
                    out.print("}");
                    if (pi + 1 < params.length) {
                        out.print(", ");
                    }
                }
                out.println("],");

                out.println("      \"instructions\": [");
                Address nextEntry = null;
                if (i + 1 < functions.size()) {
                    Function nextFunction = functions.get(i + 1);
                    nextEntry = nextFunction != null ? nextFunction.getEntryPoint() : null;
                }
                InstructionIterator instructionIt = listing.getInstructions(entry, true);
                int instructionCount = 0;
                boolean firstInstruction = true;
                while (instructionIt.hasNext() && instructionCount < 20000) {
                    Instruction instruction = instructionIt.next();
                    if (instruction == null) {
                        continue;
                    }
                    if (nextEntry != null && instruction.getAddress().compareTo(nextEntry) >= 0) {
                        break;
                    }
                    if (!firstInstruction) {
                        out.println(",");
                    }
                    out.print("        {");
                    out.print("\"address\": ");
                    _jsonString(out, instruction.getAddress() != null ? instruction.getAddress().toString() : null);
                    out.print(", \"mnemonic\": ");
                    _jsonString(out, instruction.getMnemonicString());
                    out.print(", \"text\": ");
                    _jsonString(out, instruction.toString());
                    out.print("}");
                    firstInstruction = false;
                    instructionCount += 1;
                }
                out.println("");
                out.println("      ],");
                out.print("      \"instructions_total\": ");
                out.print(instructionCount);
                out.println(",");

                Integer total = xrefsTotal.get(entry);
                out.print("      \"xrefs_to_entry_total\": ");
                out.print(total != null ? total.intValue() : 0);
                out.println(",");

                out.println("      \"xrefs_to_entry\": [");
                List<Xref> xrefs = xrefsToEntry.get(entry);
                if (xrefs != null) {
                    for (int xi = 0; xi < xrefs.size(); xi++) {
                        Xref xr = xrefs.get(xi);
                        out.print("        {");
                        out.print("\"from\": ");
                        _jsonString(out, xr.from);
                        out.print(", \"type\": ");
                        _jsonString(out, xr.type);
                        out.print("}");
                        if (xi + 1 < xrefs.size()) {
                            out.print(",");
                        }
                        out.println("");
                    }
                }
                out.println("      ],");

                out.println("      \"callers\": [");
                Set<Address> cs = callers.get(entry);
                if (cs != null) {
                    int ci = 0;
                    for (Address c : cs) {
                        Function cf = byEntry.get(c);
                        out.print("        {");
                        out.print("\"entry\": ");
                        _jsonString(out, c != null ? c.toString() : null);
                        out.print(", \"name\": ");
                        _jsonString(out, cf != null ? cf.getName() : null);
                        out.print("}");
                        ci += 1;
                        if (ci < cs.size()) {
                            out.print(",");
                        }
                        out.println("");
                    }
                }
                out.println("      ],");

                out.println("      \"callees\": [");
                Set<Address> ds = callees.get(entry);
                if (ds != null) {
                    int di = 0;
                    for (Address d : ds) {
                        Function df = byEntry.get(d);
                        out.print("        {");
                        out.print("\"entry\": ");
                        _jsonString(out, d != null ? d.toString() : null);
                        out.print(", \"name\": ");
                        _jsonString(out, df != null ? df.getName() : null);
                        out.print("}");
                        di += 1;
                        if (di < ds.size()) {
                            out.print(",");
                        }
                        out.println("");
                    }
                }
                out.println("      ]");

                out.print("    }");
                if (i + 1 < functions.size()) {
                    out.print(",");
                }
                out.println("");
            }
            out.println("  ],");

            out.println("  \"callgraph_edges\": [");
            for (int ei = 0; ei < edges.size(); ei++) {
                Address[] e = edges.get(ei);
                Address from = e[0];
                Address to = e[1];
                Function fromF = byEntry.get(from);
                Function toF = byEntry.get(to);
                out.print("    {");
                out.print("\"from\": ");
                _jsonString(out, from != null ? from.toString() : null);
                out.print(", \"from_name\": ");
                _jsonString(out, fromF != null ? fromF.getName() : null);
                out.print(", \"to\": ");
                _jsonString(out, to != null ? to.toString() : null);
                out.print(", \"to_name\": ");
                _jsonString(out, toF != null ? toF.getName() : null);
                out.print("}");
                if (ei + 1 < edges.size()) {
                    out.print(",");
                }
                out.println("");
            }
            out.println("  ]");
            out.println("}");
        }
    }
}
