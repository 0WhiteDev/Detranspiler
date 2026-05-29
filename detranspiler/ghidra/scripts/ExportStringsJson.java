import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;

public class ExportStringsJson extends ghidra.app.script.GhidraScript {
    private static class StrItem {
        public final String address;
        public final String value;

        public StrItem(String address, String value) {
            this.address = address;
            this.value = value;
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

        int maxStrings = 50000;
        if (args.length >= 2) {
            try {
                maxStrings = Integer.parseInt(args[1]);
            } catch (Exception e) {
                maxStrings = 50000;
            }
        }

        Listing listing = currentProgram.getListing();
        List<StrItem> strings = new ArrayList<>();

        DataIterator it = listing.getDefinedData(true);
        while (it.hasNext()) {
            if (monitor.isCancelled()) {
                break;
            }
            Data d = it.next();
            if (d == null) {
                continue;
            }

            StringDataInstance sdi = null;
            try {
                sdi = StringDataInstance.getStringDataInstance(d);
            } catch (Exception e) {
                sdi = null;
            }
            if (sdi == null) {
                continue;
            }

            String value = null;
            try {
                value = sdi.getStringValue();
            } catch (Exception e) {
                value = null;
            }
            if (value == null) {
                continue;
            }

            Address addr = d.getAddress();
            strings.add(new StrItem(addr != null ? addr.toString() : null, value));
            if (strings.size() >= maxStrings) {
                break;
            }
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

            out.print("  \"strings_total\": ");
            out.print(strings.size());
            out.println(",");

            out.println("  \"strings\": [");
            for (int i = 0; i < strings.size(); i++) {
                if (monitor.isCancelled()) {
                    break;
                }
                StrItem s = strings.get(i);
                out.print("    {");
                out.print("\"address\": ");
                _jsonString(out, s.address);
                out.print(", \"value\": ");
                _jsonString(out, s.value);
                out.print("}");
                if (i + 1 < strings.size()) {
                    out.print(",");
                }
                out.println("");
            }
            out.println("  ]");
            out.println("}");
        }
    }
}
