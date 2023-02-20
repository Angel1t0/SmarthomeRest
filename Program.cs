using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

/************************************************ BUILDER STARTS ************************************************************/

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    o.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.TokenValidationParameters = new TokenValidationParameters
    {
        IssuerSigningKey = new SymmetricSecurityKey
            (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true
    };
});

builder.Services.AddAuthorization();

builder.Services.AddDbContext<SmarthomeContext>(options =>
    options.UseMySQL(builder.Configuration["ConnectionStrings:MySql"]));

var securityScheme = new OpenApiSecurityScheme()
{
    Name = "Authorization",
    Type = SecuritySchemeType.ApiKey,
    Scheme = "Bearer",
    BearerFormat = "JWT",
    In = ParameterLocation.Header,
    Description = "JSON Web Token based security",
};

var securityReq = new OpenApiSecurityRequirement()
{
    {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        },
        new string[] {}
    }
};

//Conexión a una base de datos en memoria
//builder.Services.AddDbContext<SmarthomeContext>(options =>
//    options.UseInMemoryDatabase("SensorsList"));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Mi SmartHomeApi", Version = "V1" });
    c.AddSecurityDefinition("Bearer", securityScheme);
    c.AddSecurityRequirement(securityReq);
});

/******************************************** BUILDER ENDS, APP STARTS ********************************************************/

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.UseAuthentication();
app.UseAuthorization();

/******************************************** SECURITY DEFINITIONS ********************************************************/

app.MapGet("/", [AllowAnonymous] () => "Mi SamartHome API");

app.MapPost("/login", [AllowAnonymous] async (User user, SmarthomeContext db) =>
{
    var userdb = await db.Users.FindAsync(user.Username);
    if (userdb is null) return Results.NotFound(user.Username);
    if (userdb.Password != user.Password) return Results.Unauthorized();
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]));
    var jwtTokenHandler = new JwtSecurityTokenHandler();
    var descriptor = new SecurityTokenDescriptor()
    {
        SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256),
        Expires = DateTime.UtcNow.AddHours(1)
    };
    var token = jwtTokenHandler.CreateToken(descriptor);
    var jwtToken = jwtTokenHandler.WriteToken(token);
    return Results.Ok(jwtToken);
});

/******************************************** CRUD ********************************************************/

app.MapGet("/sensores", [Authorize] async (SmarthomeContext db) =>
{
    return await db.Sensors.ToListAsync();
});

app.MapPost("/sensores", [Authorize] async (Sensor s, SmarthomeContext db) =>
{
    s.Date = DateTime.Now;
    db.Sensors.Add(s);
    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapPut("/sensores/{id}", [Authorize] async (int id, Sensor s, SmarthomeContext db) =>
{
    var sensor = await db.Sensors.FindAsync(id);
    if (sensor is null)
    {
        return Results.NotFound();
    }
    sensor.Name = s.Name;
    sensor.Value = s.Value;
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.MapDelete("/sensores/{id}", [Authorize] async (int id, SmarthomeContext db) =>
{
    var sensor = await db.Sensors.FindAsync(id);
    if (sensor is null)
    {
        return Results.NotFound();
    }
    db.Sensors.Remove(sensor);
    await db.SaveChangesAsync();
    return Results.NoContent();
});

app.Run();

/******************************************** CLASSES ********************************************************/

class User
{
    [Key]
    public string? Username { get; set; }
    public string? Password { get; set; }
}
class Sensor
{
    public int Id { get; set; }
    public string? Name { get; set; }
    public double Value { get; set; }
    public DateTime Date { get; set; }
}

class SmarthomeContext : DbContext
{
    public DbSet<Sensor> Sensors => Set<Sensor>();
    public DbSet<User> Users => Set<User>();
    public SmarthomeContext(DbContextOptions<SmarthomeContext> options) : base(options)
    {
    }
}