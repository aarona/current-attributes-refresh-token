class CreateSessions < ActiveRecord::Migration[8.0]
  def change
    create_table :sessions do |t|
      t.references :user, null: false, foreign_key: true
      t.string :uuid, null: false, index: { unique: true }
      t.boolean :remember_me, null: false, default: false
      t.text :user_agent
      t.string :ip_address
      t.datetime :last_accessed_at
      t.datetime :expires_at, null: false
      t.datetime :revoked_at
      t.json :metadata, default: {}

      t.timestamps
    end

    add_index :sessions, %i[user_id uuid]
    add_index :sessions, %i[expires_at revoked_at]
  end
end
