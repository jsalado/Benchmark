/**
* OWASP Benchmark Parser for Kiuwan CSV Report
*/

package org.owasp.benchmark.score.parsers;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.List;

import com.opencsv.CSVReader;

public class KiuwanCSVReader extends Reader {
	
	public TestResults parse( File f ) throws Exception {
		trace("KiuwanReader. Parsing file: " + f.getAbsolutePath());

		String version = "";		
		String filename = f.getName();
		String[] tokens = filename.split("_");
		if (null != tokens && tokens.length>1) {
			version = tokens[1];
		}
		
		TestResults tr = new TestResults("Kiuwan", true, TestResults.ToolType.SAST);
		tr.setToolVersion(version);

		CSVReader reader = new CSVReader(new InputStreamReader(new FileInputStream(f), Charset.forName("UTF-8")), ',');
		
		String[] nextLine;
		while ((nextLine = reader.readNext()) != null) {
		    TestCaseResult tcr = parseKiuwanIssue( nextLine );
            if ( tcr != null ) {
            	tr.put( tcr );
            }
		}
		
		// dump(tr);
	
		return tr;
	}
	
	private void dump(TestResults tr) {
		try {
            FileOutputStream outputStream = new FileOutputStream("c:/owasp/kiuwan-test-results.csv");
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream, "UTF-8");
            BufferedWriter writer = new BufferedWriter(outputStreamWriter);
			
			for (Integer testNumber: tr.keySet()) {
				List<TestCaseResult> results = tr.get(testNumber);
				for (TestCaseResult tcr: results) {
					writer.write(tcr.toString());
					writer.newLine();
				}			
			}
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private TestCaseResult parseKiuwanIssue(String[] issue) {
		
		String cwe = issue[1];
		String rule = issue[2];
		String path = issue[8];
		
		if (path.contains("BenchmarkTest")) {
			String testNumber = path.replaceAll(".*BenchmarkTest", "");
			testNumber = testNumber.replace(".java", "");
			
			try {
		        TestCaseResult tcr = new TestCaseResult();
				tcr.setNumber(Integer.parseInt(testNumber));
		        tcr.setCWE(cweLookup(Integer.parseInt(cwe)));
	            
		        tcr.setCategory(rule);
		        tcr.setEvidence(rule);
		        
		        trace(tcr.toString());
		        return tcr;
			} catch (Exception e) {
			}
		}

		return null;
	}
	
	
	private Integer cweLookup(int cwe) {
		switch (cwe) {
		case 326: // OPT.JAVA.SEC_JAVA.InsufficientKeySizeRule			
		case 327: // OPT.JAVA.SEC_JAVA.WeakEncryptionRule			
			return 327; // crypto

		default:
			return cwe;
		}			
	}
	
	
	private void trace(String msg) {
		//System.out.println(msg);
	}

}
