using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using OAuch.Database.Entities;
using OAuch.Shared;
using System;
using System.Collections.Generic;
using System.Text;

namespace OAuch.Database {
    public class OAuchDbContext : DbContext {
        public OAuchDbContext() : base() {

        }
        public OAuchDbContext(IConfiguration configuration) : base() {
            _configuration = configuration;
        }
        private IConfiguration _configuration;

#pragma warning disable CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.
        public DbSet<SavedCertificate> Certificates { get; set; }
        public DbSet<Site> Sites { get; set; }
        public DbSet<SerializedTestRun> SerializedTestRuns { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
#pragma warning restore CS8618 // Non-nullable field is uninitialized. Consider declaring as nullable.

        protected override void OnConfiguring(DbContextOptionsBuilder options) {
            base.OnConfiguring(options);

            IConfiguration conf;
            if (_configuration == null)
                conf = ServiceLocator.Resolve<IConfiguration>();
            else
                conf = _configuration;
            options
                .UseLazyLoadingProxies()
                .UseSqlite(conf.GetConnectionString("OAuchDbContextConnection"));
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder) {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<UserSession>().HasKey(k => new { k.Scheme, k.LoginId });
        }
    }
}
