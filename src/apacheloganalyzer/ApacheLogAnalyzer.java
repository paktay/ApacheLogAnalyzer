/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package apacheloganalyzer;

import java.io.*;
import java.util.*;
import com.google.gson.Gson;
import java.util.function.Function;

public class ApacheLogAnalyzer {

    public static void main(String[] args) throws Exception {
        
        
        String filename = args[0];
        generateFile(0, 6, filename, "ip");
        generateFile(6, 0, filename, "url");
              
        generateDetailFile(filename);
        
        

    }
    
    private static void generateFile(int _tag, int _subtag, String filename, String flag) 
            throws FileNotFoundException, IOException, Exception {
        // Read the Apache web server log file        
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        
        // Create a map to store the summary data
        Map<String, Map<String, Summary>> summary = new HashMap<>();  
        
        // Iterate over the log file and update the summary map
        String line;
        
        while ((line = reader.readLine()) != null) {
            // Split the log line into fields
            String[] fields = line.split(" ");

            // Get the IP address, URL, and HTTP status code
            String tag = fields[_tag];
            String subtag = fields[_subtag];
            String timestamp = fields[3]+ " " + fields[4];
            timestamp.replace("[", "").replace("]", "");
            
            String url = fields[6];
            
            if(FilterUrl.validate(fields[6])) {
                url = FilterUrl.stripUrl(url);
                
                int statusCode = Integer.parseInt(fields[8]);

                // If the HTTP status code is 200, update the hit counter for the IP and URL
                if (statusCode == 200) {
                                        
                    Map<String, Summary> urlSummary = summary.getOrDefault(tag, new HashMap<>());                
                    Summary summaryObject = urlSummary.getOrDefault(subtag, new Summary());
                    summaryObject.hitCount++;
                    summaryObject.totalHit++;
                    urlSummary.put(subtag, summaryObject);
                    summary.put(tag, urlSummary);                                                                            
                                       
                }
            }
        }       
        // Close the reader
        reader.close();
        
        // Sort the summary map by total hit counter descending       
        List<Map.Entry<String, Map<String, Summary>>> sortedSummary = new ArrayList<>(summary.entrySet());
        sortedSummary.sort((o1, o2) -> Integer.compare(o2.getValue().values().stream().mapToInt(summaryObject -> summaryObject.totalHit).sum(), o1.getValue().values().stream().mapToInt(summaryObject -> summaryObject.totalHit).sum()));

        writeToFile(sortedSummary, summary, "ip", "urls", filename + "_"+flag+".json");
        
        // clear hashmap
        summary = new HashMap<>();
    }
    
    
    private static void generateDetailFile(String filename) 
            throws FileNotFoundException, IOException {
        // Read the Apache web server log file        
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        
        // Create a map to store the log data per IP
        Map<String, List<LogEntry>> logDataPerIp = new HashMap<>();
        
        // Iterate over the log file and update the summary map
        String line;
        
        while ((line = reader.readLine()) != null) {
            // Split the log line into fields
            String[] fields = line.split(" ");

            // Get the IP address, URL, and HTTP status code
            String ip = fields[0];
            String url = fields[6];
            String timestamp = fields[3]+ " " + fields[4];
            timestamp.replace("[", "").replace("]", "");                      
            
            if(FilterUrl.validate(url)) {
                url = FilterUrl.stripUrl(url);
                
                int statusCode = Integer.parseInt(fields[8]);

                // If the HTTP status code is 200, update the hit counter for the IP and URL
                if (statusCode == 200) {
                    // Create a LogEntry object
                    LogEntry logEntry = new LogEntry(ip, timestamp, url);

                    // Add the LogEntry object to the list of LogEntry objects for the IP address                    
                    List<LogEntry> arr = new ArrayList<LogEntry>();
                    arr.add(logEntry);
                    logDataPerIp.computeIfAbsent(ip, k -> new ArrayList<LogEntry>()).add(logEntry); 
                }
            }
        }
              
        // Create a directory to store the split log files
        File splitLogDirectory = new File("data/" + filename.replace(".log", ""));
        if (!splitLogDirectory.exists() || !splitLogDirectory.isDirectory()) {
            System.out.println("directory not exist");
            if(splitLogDirectory.mkdir()) {
                System.out.println("create dir");
            } else {
                System.out.println("cannot create dir");
            }
        }
        
        // Write the log data per IP to JSON files
        for (Map.Entry<String, List<LogEntry>> entry : logDataPerIp.entrySet()) {
            String ipAddress = entry.getKey();
            List<LogEntry> logEntries = entry.getValue();

            // Create a JSON file for the IP address
            File logFile = new File(splitLogDirectory, ipAddress + ".json");

            // Create a JSON array to store the LogEntry objects
            List<Map<String, Object>> jsonArray = new ArrayList<>();
            for (LogEntry logEntry : logEntries) {
                Map<String, Object> jsonObject = new HashMap<>();
                jsonObject.put("ip", logEntry.getIpAddress());
                jsonObject.put("timestamp", logEntry.getTimestamp());
                jsonObject.put("url", logEntry.getUrl());

                jsonArray.add(jsonObject);
            }

            // Write the JSON array to the JSON file
            FileWriter writer = new FileWriter(logFile);
            Gson gson = new Gson();
            writer.write(gson.toJson(jsonArray));
            writer.close();

        }
        
        logDataPerIp = new HashMap<>();
    }
        
    
    private static void writeToFile(
            List<Map.Entry<String, Map<String, Summary>>> _sortedSummary, 
            Map<String, Map<String, Summary>> _summary,
            String _tag,
            String _subtag,
            String _fileName) throws Exception {
        
        // Convert the sorted summary map to a JSON array
        Gson gson = new Gson();
        List<Map<String, Object>> jsonArray = new ArrayList<>();
        for (Map.Entry<String, Map<String, Summary>> entry : _sortedSummary) {
            String tag = entry.getKey();
            Map<String, Summary> urlSummary = entry.getValue();

            Map<String, Object> jsonObject = new HashMap<>();
            jsonObject.put(_tag, tag);
            List<Map<String, Object>> urlList = new ArrayList<>();
            for (Map.Entry<String, Summary> urlEntry : urlSummary.entrySet()) {
                String subtag = urlEntry.getKey();
                Summary summaryObject = urlEntry.getValue();

                Map<String, Object> urlObject = new HashMap<>();
                //urlObject.put("url", url);
                //urlObject.put("hit_count", summaryObject.hitCount);
                urlObject.put(subtag, summaryObject.hitCount);
                urlList.add(urlObject);
            }
            jsonObject.put(_subtag, urlList);
            jsonObject.put("total_hit", _summary.get(tag).values().stream().mapToInt(summaryObject -> summaryObject.totalHit).sum());
            jsonArray.add(jsonObject);
        }

        File dataDirectory = new File("data");
        if (!dataDirectory.exists() || !dataDirectory.isDirectory()) {
            System.out.println("directory data doesn't exist");
            if(dataDirectory.mkdir()) {
                System.out.println("create data dir");
            } else {
                System.out.println("cannot create data dir");
            }
        }
        
        // Write the JSON array to a file
        FileWriter writer = new FileWriter(dataDirectory + "/" + _fileName);
        writer.write(gson.toJson(jsonArray));
        writer.close();
    }
    
    private static class Summary {
        int hitCount;
        int totalHit;
    }
    
    private static class LogEntry {
        private String ipAddress;
        private String timestamp;
        private String url;

        public LogEntry(String ipAddress, String timestamp, String url) {
            this.ipAddress = ipAddress;
            this.timestamp = timestamp;
            this.url = url;
        }

        public String getIpAddress() {
            return ipAddress;
        }

        public void setIpAddress(String ipAddress) {
            this.ipAddress = ipAddress;
        }

        public String getTimestamp() {
            return timestamp;
        }

        public void setTimestamp(String timestamp) {
            this.timestamp = timestamp;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }

    
    private static class FilterUrl {
        static List<String> urls = Arrays.asList(
                "business.calendar_",
                "business.e_ipo_",
                "business.market_",
                "business.indices_",
                "business.forex_",
                "business.metal_",
                "business.movers_",
                "business.news_",
                "business.news_story_",
                "business.special_notation_",
                "business.stock_analytics_",
                "business.stock_corpaction_",
                "business.stock_financial_",
                "business.stock_keystats_",
                "business.stock_last_",
                "business.stock_news_",
                "business.stock_overview_",
                "business.stock_profile_",
                "business.watchlist_",
                "stk_30days_diary.jsp",
                "idx_30days_diary.jsp"
        );
        
        public static String stripUrl(String url) {
            String result = url;
            
            if(url.contains("stk_30days_diary.jsp")) {
                result = "/stk_30days_diary.jsp";
            } else if(url.contains("idx_30days_diary.jsp")) {
                result = "/idx_30days_diary.jsp";
            }
                
            return result;
        }
        
        public static boolean validate(String url) {
            boolean result = false;
            for (String element : urls){
                if(url.contains(element)){
                    result = true;
                    break;
                }            
            }
            return result;
        }
    }
}
