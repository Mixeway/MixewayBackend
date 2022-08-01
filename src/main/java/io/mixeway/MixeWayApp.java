package io.mixeway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

@SpringBootApplication(exclude = { SecurityAutoConfiguration.class})
@EnableScheduling
@EnableJpaRepositories("io.mixeway.db.repository")
@EntityScan(basePackages = "io.mixeway.db.entity")
@EnableJpaAuditing
public class MixeWayApp {


	public static void main(String[] args) {
        SpringApplication.run(MixeWayApp.class, args);
  
    }
	@Bean
	public TaskScheduler taskScheduler() {
		final ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
		scheduler.setPoolSize(16);
		scheduler.setRemoveOnCancelPolicy(true);
		return scheduler;
	}
	
}
