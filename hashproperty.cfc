<cfcomponent mixin="model" output="false">

	<cffunction name="init" access="public" output="false">
		<cfscript>
			this.version = "1.1.7,1.1.8";	
		</cfscript>
		<cfreturn this />
	</cffunction>
	
	<cffunction name="hashProperty" access="public" output="false" returntype="void">
		<cfargument name="property" type="string" required="false" default="" />
		<cfargument name="algo" type="string" required="false" default="bcrypt" hint="Can be one of `SHA-256`, `SHA-512` or `bcrypt`." />
    <cfargument name="encoding" type="string" required="false" default="" hint="Only used if the plugin uses the internal Hash() function." />
		<cfargument name="rounds" type="string" required="false" default="12" hint="The number of times to hash the hash. This number will be an exponent of 2 so don't make it too big. example: 12 would be 2^12=4096 actual rounds." />
		<cfargument name="salt" type="string" required="false" default="Th!5IsAcra3y5a1tStr!nG$" hint="Used for any algo other than bcrypt to help further protect passwords from cracking." />
		<cfscript>
			var loc = {};

			// normalize our arguments
			if (!StructKeyExists(arguments, "properties"))
				arguments.properties = arguments.property;

			// make sure we have space to save our property info
			if (!structKeyExists(variables.wheels.class, "hashproperties"))
				variables.wheels.class.hashproperties = {};

			if (!structKeyExists(variables.wheels.class, "bcrypt") and arguments.algo == "bcrypt")
				variables.wheels.class.bcrypt = $createBcryptJavaLoader().create("org.mindrot.jbcrypt.BCrypt").init();

			for (loc.property in listToArray(arguments.properties))
				variables.wheels.class.hashproperties[loc.property] = { algo = arguments.algo, encoding = arguments.encoding, rounds = arguments.rounds, salt = arguments.salt };
			
			afterValidation(method="$hashProperties");
		</cfscript>
		<cfreturn />
	</cffunction>

	<cffunction name="checkHash" access="public" output="false" returntype="boolean">
		<cfargument name="property" type="string" required="true" />
		<cfargument name="candidate" type="string" required="true" />
		<cfscript>
			var loc = { properties = variables.wheels.class.hashproperties };

			if (!structKeyExists(loc.properties, arguments.property))
				return false;

			if (loc.properties[arguments.property].algo == "bcrypt")
				return variables.wheels.class.bcrypt.checkpw(arguments.candidate, this[arguments.property]);
		</cfscript>
		<cfreturn compare($hash(value=arguments.candidate, argumentCollection=loc.properties[arguments.property]), this[arguments.property]) == 0 />
	</cffunction>

	<cffunction name="$hash" access="public" output="false" returntype="string">
		<cfargument name="value" type="string" required="true" />
		<cfargument name="algo" type="string" required="true" />
		<cfargument name="salt" type="string" required="true" />
		<cfargument name="rounds" type="numeric" required="true" />
		<cfargument name="encoding" type="string" required="false" default="" />
		<cfscript>
			var loc = {};

			switch (arguments.algo)
			{
				case "bcrypt":
					return variables.wheels.class.bcrypt.hashpw(arguments.value, variables.wheels.class.bcrypt.gensalt(javaCast("int", arguments.rounds)));
					break;
				
				default:
					// we are dealing with normal hashing so do our own rounds
					loc.value = arguments.value;
					loc.rounds = 2 ^ arguments.rounds;

					for (loc.i = 1; loc.i lte loc.rounds; loc.i++)
						loc.value = hash(loc.value & "::" & arguments.salt, arguments.algo, arguments.encoding);

					return loc.value;
					break;
			}
		</cfscript>
	</cffunction>

	<cffunction name="$hashProperties" access="public" output="false" returntype="void">
		<cfargument name="properties" type="struct" required="false" default="#variables.wheels.class.hashproperties#" />
		<cfscript>
			var loc = {};

			for (loc.property in arguments.properties)
				if (hasChanged(loc.property) and structKeyExists(this, loc.property))
					this[loc.property] = $hash(value=this[loc.property], argumentCollection=arguments.properties[loc.property]);
		</cfscript>
	</cffunction>

	<cffunction name="$createBcryptJavaLoader" access="public" output="false" returntype="any">
		<cfscript>
			var loc = {};
			
			if (!StructKeyExists(server, "javaloader") || !IsStruct(server.javaloader))
				server.javaloader = {};
			
			if (StructKeyExists(server.javaloader, "hashproperty"))
				return server.javaloader.hashproperty;
			
			loc.relativePluginPath = application.wheels.webPath & application.wheels.pluginPath & "/hashproperty/";
			loc.classPath = Replace(Replace(loc.relativePluginPath, "/", ".", "all") & "javaloader", ".", "", "one");
			
			loc.paths = ArrayNew(1);
			loc.paths[1] = ExpandPath(loc.relativePluginPath & "lib/jbcrypt-0.4.jar");
			
			// set the javaLoader to the request in case we use it again
			server.javaloader.hashproperty = $createObjectFromRoot(path=loc.classPath, fileName="JavaLoader", method="init", loadPaths=loc.paths, loadColdFusionClassPath=false);
		</cfscript>
		<cfreturn server.javaloader.hashproperty />
	</cffunction>
	
</cfcomponent>