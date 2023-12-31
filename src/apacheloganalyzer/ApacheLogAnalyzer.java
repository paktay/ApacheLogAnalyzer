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
        // Read the Apache web server log file        
        BufferedReader reader = new BufferedReader(new FileReader(args[0]));

        // Create a map to store the summary data
        //Map<String, Map<String, Summary>> summary = new HashMap<>();
        Map<String, Map<String, Object>> summary = new HashMap<>();
        Map<String, Map<String, Summary>> summary2 = new HashMap<>();
        
        // Create a map to store the log data per IP
        Map<String, List<LogEntry>> logDataPerIp = new HashMap<>();
        
        // Iterate over the log file and update the summary map
        String line;
        int lineNumber = 1;
        int jsonFileNumber = 1;
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
                    Map<String, Object> urlSummary = summary.getOrDefault(ip, new HashMap<>());
                    //List<Map<String, Integer>> urlList = (List) urlSummary.get("urls");
                    //List<Map<String, Integer>> urlList = (List) urlSummary.getOrDefault("urls", new ArrayList<>());
                    Map<String, Integer> urlList = (Map<String, Integer>) urlSummary.getOrDefault("urls", new HashMap<>());
                    urlList.put(url, urlList.getOrDefault(url, 0) + 1);
                    //urlList = checkIfKeyExists(urlList, url);
                    
                    /*
                    if(hitCount == 0) {
                        Map<String, Integer> urlObj = new HashMap<>();
                        urlObj.put(url, ++hitCount);
                        urlList.add(urlObj);
                    } else {
                        urlList.get
                    }
                    */
                    //Integer hitCount = (Integer) urlSummary.getOrDefault(url, (Object) 0);
                    Integer total_hit = (Integer) urlSummary.getOrDefault("total_hit", (Object) 0);                    
                    urlSummary.put("urls", urlList);
                    urlSummary.put("total_hit", ++total_hit);
                    summary.put(ip, urlSummary);
                    
                    /*
                    Map<String, Summary> urlSummary = summary.getOrDefault(ip, new HashMap<>());                
                    Summary summaryObject = urlSummary.getOrDefault(url, new Summary());
                    summaryObject.hitCount++;
                    summaryObject.totalHit++;
                    urlSummary.put(url, summaryObject);
                    summary.put(ip, urlSummary);
                    
                    Map<String, Summary> ipSummary = summary2.getOrDefault(url, new HashMap<>());                
                    Summary summaryObject2 = ipSummary.getOrDefault(ip, new Summary());
                    summaryObject2.hitCount++;
                    summaryObject2.totalHit++;
                    ipSummary.put(ip, summaryObject2);
                    summary2.put(url, ipSummary);
                    
                    // Create a LogEntry object
                    LogEntry logEntry = new LogEntry(ip, timestamp, url);

                    // Add the LogEntry object to the list of LogEntry objects for the IP address                    
                    List<LogEntry> arr = new ArrayList<LogEntry>();
                    arr.add(logEntry);
                    logDataPerIp.computeIfAbsent(ip, k -> new ArrayList<LogEntry>()).add(logEntry);                   
                    */
                    
                    if (lineNumber++ >= 10000) {
                        lineNumber = 1;
                        
                        writeToJsonFile(summary, jsonFileNumber);
                        jsonFileNumber++;
                        summary = new HashMap<>();
                    }
                }
            }
        }
        
        if(lineNumber >= 1) {
            writeToJsonFile(summary, jsonFileNumber);
            //jsonFileNumber++;
            //summary = new HashMap<>();
        }

        // Close the reader
        reader.close();

        // Sort the summary map by total hit counter descending
        /*
        List<Map.Entry<String, Map<String, Summary>>> sortedSummary = new ArrayList<>(summary.entrySet());
        sortedSummary.sort((o1, o2) -> Integer.compare(o2.getValue().values().stream().mapToInt(summaryObject -> summaryObject.totalHit).sum(), o1.getValue().values().stream().mapToInt(summaryObject -> summaryObject.totalHit).sum()));

        List<Map.Entry<String, Map<String, Summary>>> sortedSummary2 = new ArrayList<>(summary2.entrySet());
        sortedSummary2.sort((o1, o2) -> Integer.compare(o2.getValue().values().stream().mapToInt(summaryObject2 -> summaryObject2.totalHit).sum(), o1.getValue().values().stream().mapToInt(summaryObject2 -> summaryObject2.totalHit).sum()));

        writeToFile(sortedSummary, summary, "ip", "urls", args[0] + "1.json");
        writeToFile(sortedSummary2, summary2, "url", "ips", args[0] + "2.json");
              
        // Create a directory to store the split log files
        File splitLogDirectory = new File(args[0].replace(".log", ""));
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
*/
    }
    
    private static void writeToJsonFile(Map<String, Map<String, Object>> _summary, int _jsonFileNumber) {
        Gson gson = new Gson();
        String json = gson.toJson(_summary);
        try {
        FileWriter writer = new FileWriter("output"+ _jsonFileNumber +".json");
        writer.write(json);
        writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        /*
        _summary.forEach((key, value) -> {
            System.out.println(key);            
        });
*/
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

        // Write the JSON array to a file
        FileWriter writer = new FileWriter(_fileName);
        writer.write(gson.toJson(jsonArray));
        writer.close();
    }
    
    public static List<Map<String, Integer>> checkIfKeyExists(List<Map<String, Integer>> maps, String key) {               
        boolean isExist = false;
        if(maps != null && maps.size() > 0) {
            for (Map<String, Integer> map : maps) {            
                if (map.containsKey(key)) {
                    map.put(key, map.getOrDefault(key, 0) + 1);
                    isExist = true;
                    break;
                }                        
            }
            if (!isExist) {
                Map<String, Integer> map = new HashMap<>();
                map.put(key, map.getOrDefault(key, 0) + 1);
                maps.add(map);
            }
        } else {            
            Map<String, Integer> map = new HashMap<>();
            map.put(key, map.getOrDefault(key, 0) + 1);
            maps.add(map);            
        }
        return maps;
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
