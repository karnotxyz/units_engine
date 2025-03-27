# Class Visibility and Access Control Lists (ACLs)

## Default Visibility

- By default on Starknet, any declared class is public and accessible to all.
- When declaring classes through Units, the default behavior maintains this public visibility since the Starknet RPC specification doesn't support additional visibility parameters.

## Units RPC Enhanced Visibility Control

When using the Units RPC, you gain additional control over class visibility:

- You can explicitly set and manage visibility settings
- Visibility can be modified in two ways:
  1. Adding addresses to grant read access
  2. Revoking addresses to remove read access
- Classes can be set to public mode where everyone has read access

## Permanent Public Mode

- A special "permanent public" mode will be available
- Once set to permanent public, the visibility cannot be revoked
- This feature is particularly useful for:
  - Common contracts like ERC20
  - Token standards like ERC3643
  - Any contract where users need guaranteed permanent queryability

## Multiple Declarations

- Multiple users can declare the same class
- The class will only be declared once on the chain
- The Access Control List (ACL) for such classes will be the union of all individual ACLs
- This means if multiple users declare the same class with different visibility settings, the resulting visibility will combine all access permissions
