package com.example.logisticsapi;

import com.example.logisticsapi.util.DatabaseSeeding;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class LogisticsApiApplication implements CommandLineRunner {

    private final DatabaseSeeding databaseSeeding;

    @Autowired
    public LogisticsApiApplication(DatabaseSeeding databaseSeeding) {
        this.databaseSeeding = databaseSeeding;
    }

    public static void main(String[] args) {
        SpringApplication.run(LogisticsApiApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        databaseSeeding.seed();
    }
}
