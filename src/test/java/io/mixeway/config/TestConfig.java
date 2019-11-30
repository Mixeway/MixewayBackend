package io.mixeway.config;


import static java.lang.String.format;

import java.sql.SQLException;
import java.util.Properties;

import javax.sql.DataSource;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.JpaVendorAdapter;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.testcontainers.containers.PostgreSQLContainer;

import liquibase.integration.spring.SpringLiquibase;

/**
 * @author romeh
 */
@Configuration
@EnableJpaRepositories(basePackages = {"io.mixeway.db.repository"})
@EntityScan(basePackages = {"io.mixeway.db.entity"})
@Profile("DaoTest")
public class TestConfig {
    @Bean
    public PostgreSQLContainer postgreSQLContainer() {
        final PostgreSQLContainer postgreSQLContainer = new PostgreSQLContainer();
        postgreSQLContainer.start();
        return postgreSQLContainer;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
        return bCryptPasswordEncoder;
    }
    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.postgresql.Driver");
        ds.setUrl(format("jdbc:postgresql://%s:%s/%s",
                postgreSQLContainer().getContainerIpAddress(),
                postgreSQLContainer().getMappedPort(
                        PostgreSQLContainer.POSTGRESQL_PORT), postgreSQLContainer().getDatabaseName()));
        ds.setUsername(postgreSQLContainer().getUsername());
        ds.setPassword(postgreSQLContainer().getPassword());
        ds.setSchema(postgreSQLContainer().getDatabaseName());
        return ds;
    }

    @Bean
    public JpaTransactionManager transactionManager(LocalContainerEntityManagerFactoryBean localContainerEntityManagerFactoryBean) {
        JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setNestedTransactionAllowed(true);
        transactionManager.setEntityManagerFactory(entityManagerFactory().getObject());

        return transactionManager;
    }

    @Bean
    public PersistenceExceptionTranslationPostProcessor exceptionTranslation() {
        return new PersistenceExceptionTranslationPostProcessor();
    }

    @Bean
    public SpringLiquibase liquibase(DataSource dataSource) throws SQLException {
        tryToCreateSchema(dataSource);
        SpringLiquibase liquibase = new SpringLiquibase();
        liquibase.setDropFirst(true);
        liquibase.setDataSource(dataSource);
        liquibase.setDefaultSchema("test");
        //liquibase.setIgnoreClasspathPrefix(false);
        liquibase.setChangeLog("classpath:db/changelog/db.changelog-master.sql");
        return liquibase;
    }


    /**
     * @return the hibernate properties
     */
    private Properties getHibernateProperties() {
        Properties ps = new Properties();
        ps.put("hibernate.dialect", "org.hibernate.dialect.PostgreSQLDialect");
        ps.put("spring.jpa.open-in-view", "false");
        ps.put("spring.jpa.properties.hibernate.enable_lazy_load_no_trans", "false");
        ps.put("spring.jpa.properties.hibernate.temp.use_jdbc_metadata_defaults", "false");
        ps.put("spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation","true");
        ps.put("hibernate.jdbc.lob.non_contextual_creation","true");
        return ps;

    }

    private void tryToCreateSchema(DataSource dataSource) throws SQLException {
        String CREATE_SCHEMA_QUERY = "CREATE SCHEMA IF NOT EXISTS test";
        dataSource.getConnection().createStatement().execute(CREATE_SCHEMA_QUERY);
    }
    @Bean
    public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(dataSource());
        em.setPackagesToScan("io.mixeway.db.entity");
        JpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        em.setJpaVendorAdapter(vendorAdapter);
        em.setJpaProperties(getHibernateProperties());

        return em;
    }
}
