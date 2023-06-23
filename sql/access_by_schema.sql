/*
Returns a list of all users with access to a given schema, including the permissions 
that grant access to the schema and all tables exposed by those permissions.

Parameters:
-----------
schema : str
    The name of the database schema to query (eg, 'M_HRDW1').
*/


with schema_roles as (
  select distinct
    grantee,
    owner
  from dba_tab_privs
  where
    owner = :schema
),

permissions as (
  select
    grantee,
    granted_role,
    connect_by_root granted_role as root,
    substr(sys_connect_by_path(granted_role, '.'), 2) as path
  from dba_role_privs
  start with granted_role in (select grantee from schema_roles)
  connect by granted_role = prior grantee
),

final as (
  select
    :schema as schema,
    a.grantee as username,
    listagg(distinct a.path, chr(10)) within group (order by a.path) as permissions,
    listagg(distinct b.table_name, chr(10)) within group (order by b.table_name) as tables
  from permissions a
    join dba_tab_privs b on a.root = b.grantee and b.owner = :schema
  where
    -- only return actual users
    a.grantee in (select username from all_users)
  group by :schema, a.grantee
)

select * from final order by username
